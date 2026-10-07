"""
core/aggregator.py
Detecta automaticamente o parser correto e agrega todos os relatórios
importados — e persiste os findings resultantes (core/finding_store.py) em
vez de mantê-los só em memória.

Antes, all_vulnerabilities era só a soma de report.vulnerabilities de todos
os relatórios importados NESTA sessão: fechar o app e abrir de novo perdia
tudo. Agora, self._vulns é carregado de data/findings.json na construção e
é a fonte da verdade; cada import faz merge por fingerprint (não por id —
ver core/finding_identity.py) contra o que já está persistido, preservando
status e asset_id de findings já triados (documento de evolução dos
Findings, seções 2/3/6/7) e salva de volta no disco.

self._reports continua existindo só para o que é informação DA SESSÃO
ATUAL (contagem "importado: X — Y achados", cobertura desta sessão) — não
é mais a fonte dos achados em si.
"""
from pathlib import Path
from core.models import ScanReport, Vulnerability
from core import finding_store
from parsers.semgrep_parser import SemgrepParser
from parsers.zap_parser import ZapParser
from parsers.snyk_parser import SnykParser
from parsers.gitleaks_parser import GitleaksParser
from parsers.trivy_parser import TrivyParser
from parsers.grype_parser import GrypeParser

# Ordem de tentativa na detecção automática
PARSERS = [
    GitleaksParser(),  # primeiro — estrutura muito específica
    TrivyParser(),      # também específico (chaves 'SchemaVersion' / 'Results')
    GrypeParser(),       # idem ('matches' na raiz)
    SnykParser(),
    SemgrepParser(),
    ZapParser(),
]


class Aggregator:
    """
    Mantém a lista de relatórios importados nesta sessão e expõe a lista
    consolidada e PERSISTIDA de vulnerabilidades (ver core/finding_store.py).
    """

    def __init__(self):
        self._reports: list[ScanReport] = []
        self._vulns: list[Vulnerability] = finding_store.load_all()

    def import_file(self, file_path: str, scan_id: str | None = None) -> ScanReport:
        """
        Tenta detectar o parser correto, importa o arquivo e mescla os
        achados com o que já está persistido (por fingerprint — mesmo
        relatório importado duas vezes não duplica findings).
        Lança ValueError se nenhum parser reconhecer o formato.
        """
        path = str(Path(file_path).resolve())

        for parser in PARSERS:
            if parser.can_parse(path):
                report = parser.parse(path)
                self._reports.append(report)
                self._merge_and_persist(report.vulnerabilities, scan_id)
                return report

        raise ValueError(
            f"Formato não reconhecido: {file_path}\n"
            "Verifique se o arquivo é um relatório válido de "
            "Semgrep, ZAP, Snyk, Gitleaks, Trivy ou Grype."
        )

    def _merge_and_persist(self, incoming: list[Vulnerability], scan_id: str | None) -> dict:
        merged, stats = finding_store.upsert(self._vulns, incoming, scan_id=scan_id)
        self._vulns = merged
        finding_store.save_all(self._vulns)
        return stats

    def persist(self):
        """Salva o estado atual — chamado depois de mudança de status/ativo
        feita em memória pela UI (ver ui/main_window.py::_on_status_changed
        e _on_asset_assigned), senão a triagem manual continuaria se
        perdendo ao fechar o app mesmo com os findings já persistidos."""
        finding_store.save_all(self._vulns)

    @property
    def reports(self) -> list[ScanReport]:
        return list(self._reports)

    @property
    def all_vulnerabilities(self) -> list[Vulnerability]:
        """Todas as vulnerabilidades persistidas (não só as desta sessão)."""
        return list(self._vulns)

    def filter(
        self,
        severity: str | None = None,
        tool: str | None = None,
        status: str | None = None,
    ) -> list[Vulnerability]:
        """Filtra vulnerabilidades por severidade, ferramenta ou status."""
        result = self.all_vulnerabilities
        if severity:
            result = [v for v in result if v.severity.value == severity]
        if tool:
            result = [v for v in result if v.tool == tool]
        if status:
            result = [v for v in result if v.status.value == status]
        return result

    def clear(self):
        """"Limpar": remove os findings persistidos também (data/findings.json),
        não só o que estava em memória — ver ui/main_window.py::_on_clear e o
        texto de confirmação atualizado lá."""
        self._reports.clear()
        self._vulns = []
        finding_store.save_all(self._vulns)
