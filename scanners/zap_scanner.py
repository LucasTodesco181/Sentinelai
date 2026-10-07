"""
scanners/zap_scanner.py
Executa o OWASP ZAP internamente (DAST — a única categoria que a ASPM ainda
importava só manualmente).

Diferença importante para os outros scanners (Trivy/Semgrep/Gitleaks): eles
analisam uma PASTA de código; o ZAP ataca uma aplicação já rodando, então o
`target` aqui é sempre uma URL viva (ex.: http://localhost:3000), nunca um
caminho de arquivo.

Rodamos o "baseline scan" (zap-baseline.py) — passivo, sobe a aplicação num
spider rápido e escuta o tráfego, sem tentar exploração ativa. É seguro
contra um ambiente de desenvolvimento/staging e rápido o suficiente pra
rodar dentro do fluxo normal da ASPM (um "full scan" ativo demoraria muito
mais e é mais próximo de um pentest do que de um scan de rotina).

Duas formas de execução, na ordem de preferência:

  1) Docker (recomendado): usa a imagem oficial `zaproxy/zap-stable`, sem
     precisar instalar o ZAP na máquina.
         docker pull zaproxy/zap-stable
  2) Nativa: usa o `zap-baseline.py` diretamente, se já estiver no PATH
     (instalação normal do ZAP Desktop/CLI).
         https://www.zaproxy.org/download/

Rede — a pegadinha de sempre com Docker + localhost:
  No Linux, container e host podem compartilhar a rede (`--network host`),
  então "localhost" dentro do container já aponta pro host.
  No macOS/Windows (Docker Desktop) o container tem sua própria rede
  isolada — "localhost" ali é o CONTAINER, não a máquina que rodou o scan.
  Por isso, fora do Linux, reescrevemos localhost/127.0.0.1 no alvo para
  `host.docker.internal`, que o Docker Desktop resolve para o host.
"""
import platform
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from scanners.base_scanner import BaseScanner, ScannerResult, ScanCancelled

DOCKER_IMAGE = "zaproxy/zap-stable"

# Tempo máximo (minutos) que o zap-baseline.py pode gastar só na fase de
# spider (rastreando links/rotas da aplicação) antes de partir pra análise
# passiva. Sem isso o padrão do próprio ZAP é ficar até achar que varreu
# tudo, o que numa app maior facilmente passa dos 300s que usávamos como
# timeout do processo inteiro (foi o que aconteceu no teste com a Juice
# Shop — a Juice Shop tem bastante rota e SPA, o spider sozinho já estourou
# os 5 minutos). Limitar aqui deixa a duração previsível.
SPIDER_MINUTES = 5

# Timeout do processo (subprocess) inteiro: precisa cobrir spider (acima)
# + análise passiva + geração do relatório, e ainda sobrar folga pra
# primeira execução, quando o `docker run` ainda baixa a imagem
# zaproxy/zap-stable (~500MB+) antes de sequer começar o scan.
DEFAULT_TIMEOUT = 900  # 15 min


class ZapScanner(BaseScanner):
    name = "zap"

    def _docker_available(self) -> bool:
        return shutil.which("docker") is not None

    def _native_available(self) -> bool:
        return shutil.which("zap-baseline.py") is not None

    def is_installed(self) -> bool:
        return self._docker_available() or self._native_available()

    def install_hint(self) -> str:
        return (
            "OWASP ZAP não encontrado no PATH desta máquina (nem Docker, nem zap-baseline.py).\n"
            "Opção mais simples (Docker): instale o Docker e rode\n"
            "  docker pull zaproxy/zap-stable\n"
            "Ou instale o ZAP e garanta que zap-baseline.py está no PATH:\n"
            "  https://www.zaproxy.org/download/\n"
            "O alvo deste scan é uma URL viva (ex.: http://localhost:3000), não uma pasta."
        )

    @staticmethod
    def _normalize_target(target: str) -> str:
        target = (target or "").strip()
        if target and not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        return target

    @staticmethod
    def _rewrite_for_docker(url: str) -> str:
        """Ver docstring do módulo — só reescreve fora do Linux."""
        if platform.system() == "Linux":
            return url
        parsed = urlparse(url)
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            return url
        netloc = "host.docker.internal"
        if parsed.port:
            netloc += f":{parsed.port}"
        return parsed._replace(netloc=netloc).geturl()

    def run(self, target: str, timeout: int = DEFAULT_TIMEOUT) -> ScannerResult:
        target = self._normalize_target(target)
        if not target:
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error="Informe a URL da aplicação a escanear (ex.: http://localhost:3000).",
            )

        if not self.is_installed():
            return ScannerResult(tool=self.name, report_path="", success=False, error=self.install_hint())

        report_path = self._new_report_path()  # único por execução (ver BaseScanner)
        report_name = Path(report_path).name
        work_dir = Path(report_path).parent

        use_docker = self._docker_available()
        if use_docker:
            cmd = ["docker", "run", "--rm", "-v", f"{work_dir}:/zap/wrk/:rw"]
            if platform.system() == "Linux":
                cmd += ["--network", "host"]
            else:
                cmd += ["--add-host", "host.docker.internal:host-gateway"]
            cmd += [
                DOCKER_IMAGE, "zap-baseline.py",
                "-t", self._rewrite_for_docker(target),
                "-J", report_name,
                "-m", str(SPIDER_MINUTES),
                "-I",  # não falhar (returncode) por WARN — só nos importa o relatório gerado
            ]
        else:
            cmd = ["zap-baseline.py", "-t", target, "-J", report_name,
                   "-m", str(SPIDER_MINUTES), "-I"]

        try:
            proc = self._run_process(cmd, timeout, cwd=None if use_docker else str(work_dir))
        except ScanCancelled:
            raise  # sobe até o ScanWorker, que interrompe os scanners seguintes
        except subprocess.TimeoutExpired:
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error=f"ZAP excedeu o tempo limite de {timeout}s para o alvo '{target}'.",
            )
        except Exception as e:
            return ScannerResult(tool=self.name, report_path="", success=False, error=str(e))

        # zap-baseline.py retorna código != 0 sempre que encontra QUALQUER
        # alerta (mesmo com -I) — isso não é falha de execução, é o scan
        # funcionando. Igual Trivy/Semgrep: o sinal real de sucesso é o
        # relatório ter sido gerado, não o returncode.
        if not Path(report_path).exists():
            hint = ""
            if use_docker:
                hint = " Confira se o Docker consegue alcançar a URL (containers não enxergam 'localhost' do host por padrão fora do Linux)."
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error=(proc.stderr.strip() or "ZAP executou mas não gerou relatório.") + hint,
            )

        return ScannerResult(tool=self.name, report_path=report_path, success=True)
