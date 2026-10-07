"""
parsers/trivy_parser.py
Processa relatórios JSON gerados pelo Trivy — cobre 3 estágios da esteira
(Container, IaC e Secrets) num único relatório.

Gerar manualmente com:
    trivy fs     --format json -o relatorio.json <diretório>
    trivy image  --format json -o relatorio.json <imagem:tag>
    trivy config --format json -o relatorio.json <diretório-iac>

Ou automaticamente via scanners/trivy_scanner.py::TrivyScanner.run().
"""
import uuid
from datetime import datetime
from pathlib import Path

from parsers.base_parser import BaseParser, load_json
from core.models import ScanReport, Vulnerability, Severity, ScanType, Status

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "unknown":  Severity.INFO,
}


class TrivyParser(BaseParser):

    def can_parse(self, file_path: str) -> bool:
        """
        Assinatura do Trivy: chave de topo 'SchemaVersion' (maiúscula) +
        pelo menos uma outra chave típica do relatório Trivy. Não colide
        com o 'results'/'version' minúsculos do relatório do Semgrep —
        são chaves de dicionário diferentes.

        Importante: NÃO exigimos 'Results' aqui. Quando o Trivy escaneia
        um alvo e não encontra absolutamente nada (repositório limpo), ele
        às vezes omite a chave 'Results' inteira do JSON em vez de mandar
        uma lista vazia. Exigir 'Results' fazia um scan 100% limpo ser
        rejeitado como "formato não reconhecido" — um scan sem achados é
        um resultado válido (na verdade é a melhor notícia possível), não
        um erro de parsing.
        """
        try:
            data = load_json(file_path)
            if "SchemaVersion" not in data:
                return False
            return any(key in data for key in ("Results", "ArtifactName", "ArtifactType", "Trivy"))
        except Exception:
            return False

    def parse(self, file_path: str) -> ScanReport:
        data = load_json(file_path)

        # O Trivy roda em 3 modos (fs / image / config — ver TrivyMode em
        # scanners/trivy_scanner.py), e o JSON registra qual foi em
        # 'ArtifactType'. Isso importa porque o mesmo bloco 'Vulnerabilities'
        # tem significado diferente conforme o modo:
        #   - fs      -> leu package.json/pom.xml/requirements.txt de uma
        #                pasta comum -> isso é SCA (Software Composition
        #                Analysis), não tem nada de "container" nele.
        #   - image   -> CVE de pacote (SO ou linguagem) DENTRO de uma
        #                imagem Docker -> aí sim é o estágio Container.
        # Sem essa distinção, um "Escanear pasta" comum inflava o anel
        # Container do Dashboard e o anel SCA ficava sempre em branco.
        # Container só quando o alvo é de fato uma imagem (ou VM); pasta,
        # repositório git ("repository") e SBOM são dependências = SCA.
        artifact_type = str(data.get("ArtifactType", "")).lower()
        pkg_scan_type = ScanType.CONTAINER if artifact_type in ("container_image", "vm") else ScanType.SCA

        vulns: list[Vulnerability] = []

        for result in data.get("Results", []) or []:
            target = result.get("Target", "")

            # 1) CVEs em pacotes do SO ou de linguagem -> SCA (modo fs) ou Container (modo image)
            for item in result.get("Vulnerabilities", []) or []:
                severity = SEVERITY_MAP.get(str(item.get("Severity", "")).lower(), Severity.MEDIUM)

                cvss_score = None
                cvss_data = item.get("CVSS", {}) or {}
                for source in ("nvd", "redhat", "ghsa"):
                    src = cvss_data.get(source)
                    if src and "V3Score" in src:
                        cvss_score = src["V3Score"]
                        break

                pkg = item.get("PkgName", "?")
                fixed = item.get("FixedVersion")

                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title=item.get("Title") or item.get("VulnerabilityID", "Vulnerabilidade sem título"),
                    severity=severity,
                    scan_type=pkg_scan_type,
                    tool="trivy",
                    file_path=f"{target} ({pkg})",
                    cve_id=item.get("VulnerabilityID"),
                    cvss_score=cvss_score,
                    description=item.get("Description", ""),
                    remediation=(f"Atualizar {pkg} para a versão {fixed}"
                                 if fixed else "Sem correção disponível ainda."),
                    rule_id=item.get("VulnerabilityID"),
                    status=Status.OPEN,
                    found_at=datetime.now(),
                ))

            # 2) Más configurações de IaC -> estágio IaC
            for item in result.get("Misconfigurations", []) or []:
                severity = SEVERITY_MAP.get(str(item.get("Severity", "")).lower(), Severity.MEDIUM)

                line = None
                cause = item.get("CauseMetadata")
                if isinstance(cause, dict):
                    line = cause.get("StartLine")

                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title=item.get("Title", "Má configuração de IaC"),
                    severity=severity,
                    scan_type=ScanType.IAC,
                    tool="trivy",
                    file_path=target,
                    line=line,
                    description=item.get("Message") or item.get("Description", ""),
                    remediation=item.get("Resolution", ""),
                    rule_id=item.get("ID"),
                    status=Status.OPEN,
                    found_at=datetime.now(),
                ))

            # 3) Segredos expostos em camadas de imagem/arquivos -> reaproveita
            #    o ScanType.SECRETS que já existia (mesma categoria do Gitleaks)
            for item in result.get("Secrets", []) or []:
                severity = SEVERITY_MAP.get(str(item.get("Severity", "")).lower(), Severity.HIGH)

                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title=item.get("Title", "Segredo exposto"),
                    severity=severity,
                    scan_type=ScanType.SECRETS,
                    tool="trivy",
                    file_path=target,
                    line=item.get("StartLine"),
                    description=f"Categoria: {item.get('Category', 'desconhecida')}",
                    rule_id=item.get("RuleID"),
                    status=Status.OPEN,
                    found_at=datetime.now(),
                ))

        return ScanReport(
            tool="trivy",
            scan_type=pkg_scan_type,  # tipo predominante (SCA no modo fs, Container no modo
                                       # image) — os itens individuais carregam o scan_type correto cada um
            target=data.get("ArtifactName") or Path(file_path).stem,
            scanned_at=datetime.now(),
            vulnerabilities=vulns,
            raw_file=file_path,
        )
