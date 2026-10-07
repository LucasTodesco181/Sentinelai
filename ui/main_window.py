# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
ui/main_window.py
Janela principal da SentinelAI — PyQt6.
"""
import html
import os
import threading
import time
import uuid

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QStatusBar, QStackedWidget,
    QMessageBox, QButtonGroup, QFrame, QInputDialog,
)
from PyQt6.QtCore import Qt, QSize, QElapsedTimer, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QFont, QShortcut, QKeySequence

from core.aggregator import Aggregator
from core.scorer import calculate
from core.coverage import covered_scan_types, covered_scan_types_from_tools, coverage_key
from core import asset as asset_store
from core import settings as settings_store
from core import scan_history
from core import threat_intel
from ui.formatting import datetime_br, tool_label
from ui.views.dashboard_view import DashboardView
from ui.views.findings_view import FindingsView
from ui.views.ai_view import AIView
from ui.views.attack_path_view import AttackPathView
from ui.views.context_view import ContextView
from ui.views.assets_view import AssetsView
from ai.provider import LLMProvider
from ui import theme
from ui.icons import icon
from ui.easter_eggs import show_easter_egg
from scanners.trivy_scanner import TrivyScanner
from scanners.semgrep_scanner import SemgrepScanner
from scanners.gitleaks_scanner import GitleaksScanner
from scanners.zap_scanner import ZapScanner
from scanners.grype_scanner import GrypeScanner
from scanners.base_scanner import ScannerResult, ScanCancelled, BaseScanner
from ui.widgets.data_actions import DataActionsBar


# Índices da navegação lateral. A ordem aqui é a mesma do QStackedWidget e
# a mesma dos NavButton criados em _build_sidebar() — as três precisam bater.
NAV_DASHBOARD    = 0
NAV_FINDINGS     = 1
NAV_AI           = 2
NAV_ATTACK_PATH  = 3
NAV_ASSETS       = 4
NAV_CONTEXT      = 5


class ScanWorker(QObject):
    """
    Roda os scanners internos (Trivy, Semgrep, Gitleaks, Grype — ou só o ZAP, no
    fluxo de "Escanear URL") em thread separada para não travar a UI
    enquanto os processos externos executam — alguns (ex: Semgrep com
    --config auto, ou o baseline do ZAP) podem levar bastante tempo.

    Executa os scanners sequencialmente (não em paralelo) para manter o log
    de progresso simples e evitar concorrência de I/O nos relatórios
    temporários. Emite `finished` com a lista de ScannerResult ao final
    (sempre — mesmo quando algum scanner falha ou não está instalado, o
    erro vai dentro do próprio ScannerResult).
    """
    finished = pyqtSignal(list, bool)      # (resultados, cancelado?)
    progress = pyqtSignal(int, int, str)   # (etapa atual, total, nome da ferramenta)

    def __init__(self, target: str, scanners: list[BaseScanner] | None = None):
        super().__init__()
        self.target = target
        self._cancel = threading.Event()
        # Por padrão, os 4 scanners de pasta (Trivy e Grype convivem como
        # dois motores de SCA independentes — ver scanners/grype_scanner.py).
        # O fluxo de "Escanear URL (ZAP)" passa scanners=[ZapScanner()] — o
        # alvo ali é uma URL, não uma pasta, e não faz sentido rodar
        # Trivy/Semgrep/Gitleaks/Grype nela.
        self._scanners = scanners if scanners is not None else [TrivyScanner(), SemgrepScanner(), GitleaksScanner(), GrypeScanner()]
        for s in self._scanners:
            s.cancel_event = self._cancel

    def cancel(self):
        """Chamado pela UI (thread principal). O Event é thread-safe; o
        scanner em execução mata o processo externo na próxima verificação
        (a cada ~0,3s) e os seguintes nem começam."""
        self._cancel.set()

    def run(self):
        results = []
        cancelled = False
        total = len(self._scanners)
        for step, scanner in enumerate(self._scanners, 1):
            if self._cancel.is_set():
                cancelled = True
                break
            self.progress.emit(step, total, scanner.name)
            if not scanner.is_installed():
                results.append(ScannerResult(
                    tool=scanner.name, report_path="", success=False,
                    error=scanner.install_hint(),
                ))
                continue
            try:
                results.append(scanner.run(self.target))
            except ScanCancelled:
                cancelled = True
                break
        self.finished.emit(results, cancelled)


# Sem internet, não tenta de novo sozinho antes disso (o usuário pode forçar
# em Configurações -> Atualizar agora).
INTEL_RETRY_COOLDOWN = 600  # segundos


class _IntelBridge(QObject):
    """Leva o resultado da atualização de KEV/EPSS (feita numa thread comum
    do Python, daemon) de volta para a thread da interface. Emitir um sinal
    de um QObject criado na thread principal a partir de outra thread vira
    uma chamada enfileirada — o slot roda na thread da UI, com segurança.
    Thread daemon em vez de QThread: se o app for fechado no meio de um
    download lento, ele não segura o processo aberto nem gera o aviso
    "QThread destroyed while running"."""
    done = pyqtSignal(object)   # threat_intel.RefreshResult


class ClickableLabel(QLabel):
    """QLabel que aceita clique — usada só para o logo (easter egg)."""
    def __init__(self, on_click, parent=None):
        super().__init__(parent)
        self._on_click = on_click
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, event):
        self._on_click()
        super().mousePressEvent(event)


class NavButton(QPushButton):
    """
    Item de navegação da sidebar lateral (estilo Wiz): ícone + rótulo
    empilhados horizontalmente, checkable (fica "ativo" ao ser selecionado).
    Cada instância guarda o nome do ícone pra poder recolorir o ícone
    quando o estado ativo/hover muda (ícone monocromático desenhado via
    QPainter em ui/icons.py, então precisamos redesenhar com outra cor).
    """
    def __init__(self, icon_name: str, label: str, parent=None):
        super().__init__(parent)
        self._icon_name = icon_name
        self.setText(f"  {label}")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setIconSize(QSize(18, 18))
        self.setFixedHeight(42)
        self.setIcon(icon(icon_name, theme.TEXT_MUTED, 18))
        self._refresh_icon()
        self.toggled.connect(self._refresh_icon)

    def _refresh_icon(self):
        color = theme.ACCENT if self.isChecked() else theme.TEXT_MUTED
        self.setIcon(icon(self._icon_name, color, 18))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.aggregator = Aggregator()
        self.provider = LLMProvider()          # detecta Ollama ou usa Groq

        # Groq API Key persistida (ver ui/dialogs/settings_dialog.py — P2 #15):
        # sem isso, o usuário precisava redigitar a chave a cada abertura.
        saved_key = settings_store.load().groq_api_key
        if saved_key:
            self.provider.set_groq_key(saved_key)

        # --- estado dos easter eggs -----------------------------------
        self._logo_click_count = 0
        self._logo_click_timer = QElapsedTimer()

        # --- estado do scan interno -------------------------------------
        self._scan_thread = None
        self._scan_worker = None
        self._action_bars: list[DataActionsBar] = []
        # scan_id + cronômetro da execução em andamento — usados para
        # registrar em core/scan_history.py e marcar Vulnerability.scan_id
        # dos achados desta execução (ver _on_scan_folder/_on_scan_finished).
        self._current_scan_id: str | None = None
        self._scan_target: str = ""
        self._scan_timer = QElapsedTimer()

        # --- inteligência de ameaças (CISA KEV + EPSS) --------------------
        # Tem que existir antes de _setup_ui(): a primeira _refresh_views()
        # já dispara a sincronização. Ver _sync_threat_intel().
        self._intel_bridge = _IntelBridge()
        self._intel_bridge.done.connect(self._on_intel_done)
        self._intel_running = False
        self._intel_manual = False
        self._intel_last_fail: float | None = None

        self._setup_ui()
        self._setup_easter_eggs()

    # ------------------------------------------------------------------
    def _setup_ui(self):
        self.setWindowTitle("SentinelAI — Application Security Posture Management")
        # Era 1280x800 — maior que a resolução de trabalho de muita gente
        # (ex.: notebook 1366x768 com barra de tarefas, ou qualquer tela
        # em ~125% de escala), o que forçava a janela a nascer cortada ou
        # impedia redimensionar pra caber (P0 #2 da revisão de UI). 1024x640
        # ainda cabe todo o layout (sidebar + conteúdo) com folga.
        self.setMinimumSize(1024, 640)
        self._apply_dark_theme()

        # Widget central: sidebar lateral (esquerda) + coluna de conteúdo (direita).
        # Antes disso era um QTabWidget com abas no topo; a navegação lateral
        # (estilo Wiz) separa melhor "onde eu navego" (sidebar) de "o que eu
        # faço agora" (barra de ações no topo do conteúdo).
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_sidebar())

        content_col = QWidget()
        content_layout = QVBoxLayout(content_col)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Views — agora empilhadas num QStackedWidget, trocadas pela sidebar
        self.stack = QStackedWidget()

        self.dashboard_view    = DashboardView()
        self.findings_view     = FindingsView()
        self.ai_view           = AIView(self.provider)
        self.attack_path_view  = AttackPathView()
        self.context_view      = ContextView()
        self.assets_view       = AssetsView()
        self.context_view.context_saved.connect(self._on_context_saved)
        self.findings_view.status_changed.connect(self._on_status_changed)
        self.findings_view.asset_assigned.connect(self._on_asset_assigned)
        self.findings_view.explain_requested.connect(self._on_explain_requested)
        self.assets_view.assets_changed.connect(self._on_assets_changed)

        self.ai_view.set_intel_refresh(lambda: self._sync_threat_intel(force=True))

        self.dashboard_view.add_header_widget(self._make_data_actions())
        self.findings_view.add_header_widget(self._make_data_actions())

        # Checklist de primeiros passos (estado vazio do Dashboard) -> navegação
        self.dashboard_view.go_to_context.connect(lambda: self._go_to(NAV_CONTEXT))
        self.dashboard_view.go_to_assets.connect(lambda: self._go_to(NAV_ASSETS))
        self.context_view.go_to_assets.connect(lambda: self._go_to(NAV_ASSETS))
        self.dashboard_view.scan_requested.connect(self._on_scan_folder)
        self.dashboard_view.import_requested.connect(self._on_import)

        # Ordem tem que bater 1:1 com a ordem dos NavButton criados em _build_sidebar()
        self.stack.addWidget(self.dashboard_view)
        self.stack.addWidget(self.findings_view)
        self.stack.addWidget(self.ai_view)
        self.stack.addWidget(self.attack_path_view)
        self.stack.addWidget(self.assets_view)
        self.stack.addWidget(self.context_view)

        content_layout.addWidget(self.stack)
        root_layout.addWidget(content_col, 1)

        # Carrega os ativos já salvos (data/assets.json) e distribui para as
        # views que precisam deles — mesmo antes de qualquer import de relatório.
        self._push_assets(self.assets_view.get_assets())

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Pronto. Importe um relatório para começar.")

        # Primeira renderização: sem isso o Dashboard abriria com os widgets
        # no estado padrão do construtor, e o checklist de primeiros passos
        # não refletiria o contexto/ativos já salvos em disco.
        self._refresh_views()

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setFixedWidth(224)
        # objectName + seletor "#sidebar" — mesma correção do build_header
        # (P1 #5 da revisão de UI): sem seletor, o border-right vazava para o
        # logo e os textos "SentinelAI"/"ASPM" filhos, que ganhavam uma linha
        # vertical própria em vez de só a sidebar ter a borda.
        sidebar.setObjectName("sidebar")
        sidebar.setStyleSheet(
            f"#sidebar {{ background:{theme.BG_SURFACE_ALT}; border-right:1px solid {theme.BORDER}; }}"
        )
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 12)
        layout.setSpacing(2)

        # Marca, no topo da sidebar (era na toolbar, agora mora aqui)
        brand = QWidget()
        brand.setFixedHeight(64)
        brand_layout = QHBoxLayout(brand)
        brand_layout.setContentsMargins(18, 0, 12, 0)
        brand_layout.setSpacing(10)

        logo = ClickableLabel(self._on_logo_clicked)
        logo.setPixmap(icon("shield", theme.ACCENT, 22).pixmap(22, 22))
        brand_layout.addWidget(logo)

        brand_box = QVBoxLayout()
        brand_box.setSpacing(0)
        brand_box.setContentsMargins(0, 0, 0, 0)

        name = QLabel("SentinelAI")
        name.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        name.setStyleSheet(f"color:{theme.TEXT_PRIMARY};")
        brand_box.addWidget(name)

        subtitle = QLabel("ASPM")
        subtitle.setFont(QFont("Segoe UI", 8))
        subtitle.setStyleSheet(f"color:{theme.TEXT_MUTED}; letter-spacing:0.5px;")
        brand_box.addWidget(subtitle)

        brand_layout.addLayout(brand_box)
        brand_layout.addStretch()
        layout.addWidget(brand)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet(f"background:{theme.BORDER}; max-height:1px; border:none;")
        layout.addWidget(divider)
        layout.addSpacing(10)

        # Itens de navegação — ordem tem que bater 1:1 com o QStackedWidget
        nav_items = [
            ("dashboard", "Dashboard"),
            ("list",      "Findings"),
            ("brain",     "Inteligência Artificial"),
            ("flame",     "Attack Path"),
            ("server",    "Ativos"),
            ("shield",    "Contexto da Empresa"),
        ]

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons = []

        for idx, (icon_name, label) in enumerate(nav_items):
            btn = NavButton(icon_name, label)
            btn.setStyleSheet(self._nav_button_style())
            self.nav_group.addButton(btn, idx)
            layout.addWidget(btn)
            self.nav_buttons.append(btn)

        self.nav_buttons[0].setChecked(True)
        self.nav_group.idClicked.connect(self._on_nav_selected)

        layout.addStretch()
        return sidebar

    @staticmethod
    def _nav_button_style() -> str:
        return f"""
            QPushButton {{
                background: transparent; color: {theme.TEXT_MUTED};
                border: none; border-left: 3px solid transparent;
                text-align: left; padding-left: 15px;
                font-size: 13px;
            }}
            QPushButton:hover {{ background: {theme.BG_ELEVATED}; color: {theme.TEXT_PRIMARY}; }}
            QPushButton:checked {{
                background: {theme.BG_ELEVATED}; color: {theme.TEXT_PRIMARY};
                border-left: 3px solid {theme.ACCENT}; font-weight: bold;
            }}
        """

    def _on_nav_selected(self, idx: int):
        self.stack.setCurrentIndex(idx)

    def _go_to(self, idx: int):
        """Navega por código (usado pelo checklist de primeiros passos do
        Dashboard) — troca a página E marca o item certo na sidebar, senão o
        destaque lateral fica apontando pra tela errada."""
        self.stack.setCurrentIndex(idx)
        if 0 <= idx < len(self.nav_buttons):
            self.nav_buttons[idx].setChecked(True)

    def _make_data_actions(self) -> DataActionsBar:
        """Uma instância de ações de dados para o cabeçalho de uma view.

        Substitui a antiga topbar global (P2 #10): as ações só aparecem onde
        fazem sentido (Dashboard e Findings), no próprio cabeçalho da view, e
        todas as instâncias refletem o mesmo estado de scan em andamento."""
        bar = DataActionsBar()
        bar.scan_clicked.connect(self._on_scan_folder)
        bar.zap_scan_clicked.connect(self._on_scan_url_zap)
        bar.import_clicked.connect(self._on_import)
        bar.clear_clicked.connect(self._on_clear)
        bar.cancel_clicked.connect(self._on_cancel_scan)
        self._action_bars.append(bar)
        return bar

    # ------------------------------------------------------------------
    # Easter eggs 🥚 — 2 personagens escondidos:
    #   1) bruxo -> clicar 7x rápido no logo da toolbar
    #   2) tux   -> atalho Ctrl+Alt+T
    def _setup_easter_eggs(self):
        QShortcut(QKeySequence("Ctrl+Alt+T"), self,
                  activated=lambda: show_easter_egg(self, "tux"))

    def _on_logo_clicked(self):
        if not self._logo_click_timer.isValid() or self._logo_click_timer.elapsed() > 1200:
            self._logo_click_count = 0
        self._logo_click_timer.restart()
        self._logo_click_count += 1
        if self._logo_click_count >= 7:
            self._logo_click_count = 0
            show_easter_egg(self, "wizard")

    # ------------------------------------------------------------------
    def _on_import(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Selecione relatório(s)",
            "",
            "Relatórios (*.json *.xml);;Todos os arquivos (*)",
        )
        if not paths:
            return

        # Um scan_id por lote de importação (não um por arquivo) — os
        # arquivos escolhidos juntos no diálogo contam como uma "execução"
        # para o histórico (core/scan_history.py), mesmo sendo importação
        # manual e não um scan disparado pelo app.
        scan_id = str(uuid.uuid4())
        errors = []
        imported = 0
        tools_used: list[str] = []
        total_found = 0
        for path in paths:
            try:
                report = self.aggregator.import_file(path, scan_id=scan_id)
                imported += 1
                tools_used.append(coverage_key(report))  # "trivy-image" p/ Trivy de imagem
                total_found += len(report.vulnerabilities)
                self.status.showMessage(
                    f"Importado: {report.tool.upper()} — "
                    f"{len(report.vulnerabilities)} vulnerabilidades encontradas."
                )
            except ValueError as e:
                errors.append(str(e))
            except Exception as e:   # noqa: BLE001 — parser recebeu um relatório fora do padrão
                # Qualquer erro que escapasse de um slot do Qt derruba o app
                # inteiro (PyQt6 aborta). Um relatório estranho tem que virar
                # mensagem na tela, não um fechamento no meio da apresentação.
                errors.append(f"{os.path.basename(path)}: falha ao ler o relatório ({type(e).__name__}: {e})")

        if errors:
            QMessageBox.warning(self, "Formato não reconhecido", "\n\n".join(errors))

        if imported > 0:
            scan_history.record(
                target=f"Importação manual ({imported} arquivo(s))",
                tools=tools_used, finding_count=total_found,
                status="success" if not errors else "partial",
                scan_id=scan_id,
            )
            self._refresh_views()

    # ------------------------------------------------------------------
    # Scan interno: a ASPM dispara Trivy + Semgrep + Gitleaks + Grype
    # diretamente contra uma pasta escolhida, sem o usuário precisar rodar
    # as ferramentas por fora e importar o JSON manualmente. Trivy e Grype
    # convivem como dois motores de SCA independentes (bases de
    # vulnerabilidade diferentes — ver scanners/grype_scanner.py). Snyk
    # (precisa de auth/conta) fica fora dessa automação — continua só via
    # importação manual de relatório. O ZAP tem fluxo próprio logo abaixo
    # (_on_scan_url_zap): o alvo dele é uma URL viva, não uma pasta.
    def _on_scan_folder(self):
        if self._scan_thread is not None:
            QMessageBox.information(self, "Scan em andamento", "Já existe um scan em execução.")
            return

        folder = QFileDialog.getExistingDirectory(self, "Selecione a pasta do projeto para escanear")
        if not folder:
            return

        self._start_scan(
            target=folder,
            scanners=[TrivyScanner(), SemgrepScanner(), GitleaksScanner(), GrypeScanner()],
            status_message=f"Escaneando {folder}...",
        )

    def _on_scan_url_zap(self):
        if self._scan_thread is not None:
            QMessageBox.information(self, "Scan em andamento", "Já existe um scan em execução.")
            return

        url, ok = QInputDialog.getText(
            self, "Escanear URL (ZAP)",
            "URL da aplicação já rodando (ex.: http://localhost:3000):",
        )
        url = (url or "").strip()
        if not ok or not url:
            return

        self._start_scan(
            target=url,
            scanners=[ZapScanner()],
            status_message=f"Escaneando {url} com o ZAP...",
        )

    def _start_scan(self, target: str, scanners: list, status_message: str):
        """Fluxo comum de disparo do scan em thread separada — usado tanto
        pelo scan de pasta (Trivy/Semgrep/Gitleaks/Grype) quanto pelo scan de URL
        (ZAP), que só diferem no alvo e na lista de scanners."""
        self.status.showMessage(status_message)
        total = len(scanners)
        for bar in self._action_bars:
            bar.set_scanning(1, total, "preparando")

        self._current_scan_id = str(uuid.uuid4())
        self._scan_target = target
        self._scan_timer.start()

        self._scan_thread = QThread()
        self._scan_worker = ScanWorker(target, scanners=scanners)
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.finished.connect(self._scan_thread.quit)
        self._scan_thread.finished.connect(self._cleanup_scan_thread)

        self._scan_thread.start()

    def _on_scan_progress(self, step: int, total: int, tool: str):
        for bar in self._action_bars:
            bar.set_scanning(step, total, tool)
        self.status.showMessage(f"Scan: etapa {step} de {total} — {tool}")

    def _on_cancel_scan(self):
        if self._scan_worker is None:
            return
        self._scan_worker.cancel()
        for bar in self._action_bars:
            bar.set_cancelling()
        self.status.showMessage("Cancelando scan...")

    def _cleanup_scan_thread(self):
        if self._scan_thread is not None:
            self._scan_thread.deleteLater()
        if self._scan_worker is not None:
            self._scan_worker.deleteLater()
        self._scan_thread = None
        self._scan_worker = None
        for bar in self._action_bars:
            bar.set_idle()

    @staticmethod
    def _discard_report(path: str):
        """Apaga o relatório temporário depois de lido. Os relatórios ficam
        na pasta temp do sistema, e o do Trivy/Semgrep descreve em detalhe as
        falhas do projeto escaneado — não há motivo para deixá-los lá."""
        if path:
            try:
                os.remove(path)
            except OSError:
                pass

    def _on_scan_finished(self, results: list, cancelled: bool):
        if cancelled:
            # Cancelar = abortar: nada do que rodou até aqui é importado,
            # para o usuário não ficar com um scan pela metade misturado aos
            # dados (ex.: cancelou porque escolheu a pasta errada).
            for r in results:
                self._discard_report(r.report_path)
            self.status.showMessage("Scan cancelado — nenhum resultado foi importado.")
            return

        imported, not_installed, failed = [], [], []
        tools_used: list[str] = []
        total_found = 0
        for result in results:
            if result.success:
                try:
                    report = self.aggregator.import_file(result.report_path, scan_id=self._current_scan_id)
                    imported.append(f"{tool_label(result.tool)} — {len(report.vulnerabilities)} achado(s)")
                    tools_used.append(coverage_key(report))
                    total_found += len(report.vulnerabilities)
                except Exception as e:   # noqa: BLE001 — ver _on_import: não deixar escapar do slot
                    failed.append(f"{tool_label(result.tool)} — relatório gerado mas não pôde ser lido: {e}")
                finally:
                    self._discard_report(result.report_path)
            elif "não encontrado no PATH" in (result.error or ""):
                not_installed.append(f"{tool_label(result.tool)} — {result.error}")
            else:
                failed.append(f"{tool_label(result.tool)} — {result.error}")

        self._show_scan_result(imported, not_installed, failed)

        # Registro da execução (core/scan_history.py) — item 4 do documento
        # de evolução dos Findings ("SCAN" separado de "FINDING"). Serve
        # também pra cobertura do Dashboard continuar correta depois de
        # reabrir o app (ver core/coverage.py::covered_scan_types_from_tools).
        scan_history.record(
            target=self._scan_target, tools=tools_used, finding_count=total_found,
            status="success" if imported and not failed else ("partial" if imported else "failed"),
            duration_seconds=self._scan_timer.elapsed() / 1000.0 if self._scan_timer.isValid() else None,
            scan_id=self._current_scan_id,
        )
        self._current_scan_id = None

        if imported:
            self._refresh_views()
            self.status.showMessage(f"Scan concluído: {len(imported)} ferramenta(s) importada(s).")
        else:
            self.status.showMessage("Scan concluído sem novos achados importados.")

    def _show_scan_result(self, imported: list, not_installed: list, failed: list):
        """Resultado do scan com ícones vetoriais do app em vez dos emoji
        (visto/alerta/X) que ainda sobravam aqui (P1 #9)."""
        def section(color: str, title: str, items: list) -> str:
            # Marcador na cor semântica + título em negrito; o ícone vetorial
            # grande (visto/alerta/X) vai no próprio diálogo, abaixo.
            bullets = "".join(
                f"<li>{html.escape(x).replace(chr(10), '<br>')}</li>" for x in items)
            return (f"<p style='margin:0 0 4px 0'><b style='color:{color}'>● </b>"
                    f"<b>{html.escape(title)}</b></p><ul style='margin-top:0'>{bullets}</ul>")

        parts = []
        if imported:
            parts.append(section(theme.SUCCESS, "Importado com sucesso", imported))
        if not_installed:
            parts.append(section(theme.WARNING, "Ferramenta não instalada nesta máquina", not_installed))
        if failed:
            parts.append(section(theme.DANGER, "Falhou", failed))

        box = QMessageBox(self)
        box.setWindowTitle("Resultado do scan")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText("".join(parts) or "Nenhum resultado.")
        if imported and not failed:
            box.setIconPixmap(icon("check", theme.SUCCESS, 32).pixmap(32, 32))
        elif imported:
            box.setIconPixmap(icon("alert", theme.WARNING, 32).pixmap(32, 32))
        else:
            box.setIconPixmap(icon("x", theme.DANGER, 32).pixmap(32, 32))
        box.addButton("OK", QMessageBox.ButtonRole.AcceptRole)
        box.exec()

    def _on_context_saved(self, ctx):
        self.ai_view.set_context(ctx)
        self.status.showMessage(f"Contexto salvo: {ctx.setor} | {ctx.porte}")

    def _on_status_changed(self):
        # A Vulnerability já foi mutada em memória pelo FindingsView — só precisa
        # recalcular o score (que filtra por status == open) e refletir nas outras abas.
        # persist() grava a mudança em data/findings.json — sem isso, marcar
        # algo como "Corrigida"/"Risco aceito" se perdia ao fechar o app,
        # mesmo já com os findings persistidos (item 6 do documento de
        # evolução: status manual não pode se perder).
        self.aggregator.persist()
        self._refresh_views()
        self.status.showMessage("Status atualizado.")

    def _on_asset_assigned(self):
        # Vínculo com ativo não afeta o score de risco do Dashboard (que é só
        # severidade), mas a próxima rodada de Priorização IA já vai usar o
        # ativo certo, já que ai_view e findings_view compartilham as mesmas
        # instâncias de Vulnerability (a mutação do asset_id é vista por ambos).
        # persist() garante que o vínculo sobrevive a fechar/abrir o app
        # (item 7 do documento de evolução dos Findings).
        self.aggregator.persist()
        self.status.showMessage("Ativo vinculado.")

    def _on_explain_requested(self, vuln):
        """"Explicar com IA" no painel de detalhe de Findings."""
        self._go_to(NAV_AI)
        self.ai_view.explain(vuln)

    def _on_assets_changed(self, assets: list):
        self._push_assets(assets)
        # Ativo excluído: findings que apontavam pra ele ficavam com um
        # asset_id órfão — não apareciam em "Sem ativo" nem em nenhum ativo.
        # Solta o vínculo (os findings em si não são apagados).
        ids = {a.id for a in assets}
        orphans = [v for v in self.aggregator.all_vulnerabilities
                   if v.asset_id and v.asset_id not in ids]
        if orphans:
            for v in orphans:
                v.asset_id = None
            self.aggregator.persist()
            self._refresh_views()
        self.status.showMessage(f"{len(assets)} ativo(s) salvos.")

    def _push_assets(self, assets: list):
        """Distribui a lista de Ativos para as views que precisam deles."""
        self.findings_view.set_assets(assets)
        self.context_view.set_assets(assets)
        self.ai_view.set_assets(asset_store.as_dict(assets))
        self.attack_path_view.set_assets(asset_store.as_dict(assets))

    def _on_clear(self):
        # "Limpar" apagava tudo (scans importados, findings) sem perguntar
        # nada — um clique sem querer perdia todo o trabalho de importação.
        # Só pergunta quando há algo de fato a perder; nada importado ainda
        # -> não há por que interromper com uma confirmação vazia (P1 #6
        # da revisão de UI).
        #
        # Desde a persistência de findings (data/findings.json), "Limpar"
        # deixou de ser só um reset de sessão: agora apaga o dado do disco
        # também — por isso o texto do aviso mudou de "nesta sessão" para
        # deixar claro que é definitivo. Decisão consciente de manter um
        # único botão (em vez de separar "Limpar sessão" de "Apagar
        # histórico" como o documento de evolução permite como alternativa)
        # para não crescer a UI num app de escopo acadêmico — a confirmação
        # explícita já cobre o "nunca apagar histórico silenciosamente".
        if self.aggregator.all_vulnerabilities:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Question)
            box.setWindowTitle("Limpar dados")
            n = len(self.aggregator.all_vulnerabilities)
            box.setText(
                f"Remover definitivamente os {n} findings salvos (inclusive de scans "
                "anteriores)? Status, vínculos com ativos e o histórico de execuções "
                "de scan serão apagados do disco — essa ação não pode ser desfeita.\n\n"
                "Contexto da Empresa e o cadastro de Ativos não são afetados."
            )
            btn_clear = box.addButton("Limpar", QMessageBox.ButtonRole.YesRole)
            btn_cancel = box.addButton("Cancelar", QMessageBox.ButtonRole.NoRole)
            box.setDefaultButton(btn_cancel)
            box.exec()
            if box.clickedButton() is not btn_clear:
                return
        self.aggregator.clear()
        scan_history.clear_all()
        self._refresh_views()
        self.status.showMessage("Dados limpos.")

    def _refresh_views(self):
        vulns = self.aggregator.all_vulnerabilities
        score = calculate(vulns)
        ctx   = self.context_view.get_context()

        # Cobertura vem das FERRAMENTAS importadas, não dos achados: um scan
        # do Trivy que não encontrou nada ainda assim cobriu IaC/Container/
        # Secrets. Sem isso, um scan limpo voltaria a parecer "não escaneado".
        # self.aggregator.reports só tem os relatórios importados NESTA
        # sessão — soma com o histórico persistido (core/scan_history.py)
        # para a cobertura continuar correta depois de reabrir o app, já
        # que os findings agora sobrevivem ao fechamento mas essa lista de
        # ScanReport em memória, não.
        coverage = covered_scan_types(self.aggregator.reports) | \
            covered_scan_types_from_tools(scan_history.covered_tools())
        for bar in self._action_bars:
            bar.set_has_data(bool(vulns) or bool(self.aggregator.reports))

        self.dashboard_view.update_data(
            score, vulns,
            coverage=coverage,
            context_ok=bool(ctx and ctx.preenchido),
            assets_count=len(self.assets_view.get_assets()),
        )
        self.findings_view.update_data(vulns)
        self.ai_view.update_data(vulns)
        self.ai_view.set_context(ctx)
        self.attack_path_view.update_data(vulns)

        # CVE novo importado, ou cache de KEV/EPSS com mais de 24h -> atualiza
        # em segundo plano. Barato quando não há nada a fazer (só olha o cache).
        self._sync_threat_intel()

    # ------------------------------------------------------------------
    # Inteligência de ameaças: CISA KEV + FIRST EPSS (core/threat_intel.py)
    def _sync_threat_intel(self, force: bool = False):
        if self._intel_running:
            if force:
                self.status.showMessage("Atualização de CISA KEV / EPSS já em andamento...", 5000)
            return
        cves = [v.cve_id for v in self.aggregator.all_vulnerabilities]
        if not force:
            if not threat_intel.needs_refresh(cves):
                return
            if (self._intel_last_fail is not None
                    and time.monotonic() - self._intel_last_fail < INTEL_RETRY_COOLDOWN):
                return
        self._intel_running = True
        self._intel_manual = force
        if force:
            self.status.showMessage("Atualizando CISA KEV e EPSS em segundo plano...")
        threading.Thread(target=self._intel_worker, args=(cves, force),
                         daemon=True, name="threat-intel").start()

    def _intel_worker(self, cves: list, force: bool):
        """Roda FORA da thread da UI: só rede + cache, nenhum widget aqui."""
        try:
            result = threat_intel.refresh(cves, force=force)
        except Exception as e:   # refresh() não deveria levantar — rede de segurança
            result = threat_intel.RefreshResult(errors=[str(e)], attempted=True)
        self._intel_bridge.done.emit(result)

    def _on_intel_done(self, result):
        self._intel_running = False
        if result.errors:
            self._intel_last_fail = time.monotonic()
            error_detail = "; ".join(result.errors)
            print(f"[threat_intel] {error_detail}")
            when = datetime_br(threat_intel.status()["kev_updated_at"])
            base = (f"Sem conexão com CISA/FIRST — usando KEV/EPSS em cache de {when}."
                    if when else
                    "Sem conexão com CISA/FIRST — priorização segue sem KEV/EPSS por enquanto.")
            # O erro de verdade (timeout, SSL, DNS, HTTP 403 etc.) só ia pro
            # console antes — invisível em quem roda o .exe empacotado (sem
            # console) ou nem olha o terminal. "Sem conexão" genérico não
            # ajuda a diagnosticar proxy/firewall corporativo, por exemplo.
            # Mostramos o detalhe truncado junto, e sempre na barra de status
            # (não só quando é atualização manual), senão o refresh
            # automático engole erros silenciosamente.
            detail_short = error_detail if len(error_detail) <= 160 else error_detail[:157] + "..."
            self.status.showMessage(f"{base} Detalhe: {detail_short}", 15000)
        else:
            self._intel_last_fail = None
            if result.attempted or self._intel_manual:
                self.status.showMessage(
                    f"Inteligência de ameaças atualizada — CISA KEV: {result.kev_count} CVEs no "
                    f"catálogo · EPSS consultado para {result.epss_fetched} CVE(s).", 10000)
        if result.kev_updated or result.epss_fetched:
            # Reflete no painel de detalhe do Findings (pílula KEV, linha EPSS).
            # Não entra em loop: o cache já está fresco, ou a falha ativou o
            # intervalo de espera acima.
            self._refresh_views()

    # ------------------------------------------------------------------
    def closeEvent(self, event):
        """Pergunta antes de fechar se Contexto ou Ativos têm alterações não
        salvas (P2 #17). Antes, preencher as 8 seções do Contexto e fechar a
        janela sem clicar em Salvar descartava tudo sem aviso — Ativos só
        avisava ao trocar de item, não ao fechar."""
        pending = []
        if self.context_view.has_unsaved_changes():
            pending.append(("Contexto da Empresa", self.context_view, NAV_CONTEXT))
        if self.assets_view.has_unsaved_changes():
            pending.append(("Ativos", self.assets_view, NAV_ASSETS))

        if pending:
            names = " e ".join(n for n, _, _ in pending)
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("Alterações não salvas")
            box.setText(f"Há alterações não salvas em {names}.")
            box.setInformativeText("Deseja salvar antes de sair?")
            btn_save = box.addButton("Salvar", QMessageBox.ButtonRole.AcceptRole)
            btn_discard = box.addButton("Descartar", QMessageBox.ButtonRole.DestructiveRole)
            btn_cancel = box.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(btn_save)
            box.setEscapeButton(btn_cancel)
            box.exec()
            clicked = box.clickedButton()
            if clicked is btn_cancel or clicked is None:
                event.ignore()
                return
            if clicked is btn_save:
                for _, view, nav in pending:
                    if not view.save():
                        # validação falhou (ex.: setor não preenchido) — o
                        # próprio view já mostrou o aviso; leva o usuário até
                        # lá e mantém o app aberto.
                        self._go_to(nav)
                        event.ignore()
                        return

        # Scan em andamento: encerra o processo externo em vez de deixá-lo
        # rodando órfão depois que a janela fechar.
        if self._scan_worker is not None:
            self._scan_worker.cancel()
            if self._scan_thread is not None:
                self._scan_thread.quit()
                self._scan_thread.wait(3000)
        super().closeEvent(event)

    def _apply_dark_theme(self):
        # Navegação por abas no topo virou sidebar lateral (ver _build_sidebar).
        # OBS: isso não significa que nenhum QTabWidget resta no app — o
        # AIView usa um (self.sub_tabs) para as 4 sub-abas de IA, só que com
        # QSS próprio e escopado (#aiSubTabs), não este estilo global. Ver
        # ui/views/ai_view.py::_build_ui.
        #
        # "QMainWindow, QWidget { background: BG_APP }" é um seletor
        # universal — sem uma regra mais específica por cima, ele pinta
        # BG_APP como fundo de QUALQUER QWidget do app, inclusive os QLabel
        # simples usados em cabeçalhos (ui/widgets/view_header.py) que só
        # definem color/border:none, nunca background. Como esses labels
        # ficam sobre um QFrame com fundo mais claro (#viewHeader, BG_SURFACE),
        # cada um pintava sua própria caixa BG_APP (mais escura) atrás do
        # texto — visível como um retângulo destacado ao redor do ícone e do
        # título em TODA tela que usa build_header() (reportado por print).
        # "QLabel { background: transparent }" resolve pra qualquer label do
        # app de uma vez: um QLabel com QSS próprio mais específico (ex.:
        # badges/pills com setStyleSheet definindo background explícito)
        # continua sobrepondo essa regra normalmente — só o caso "label sem
        # background nenhum definido" para de herdar o BG_APP indevido.
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background: {theme.BG_APP}; color: {theme.TEXT_PRIMARY}; }}
            QLabel {{ background: transparent; }}
            QStatusBar {{ background: {theme.BG_SURFACE}; color: {theme.TEXT_MUTED}; font-size: 11px; }}
        """)
