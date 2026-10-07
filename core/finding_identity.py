"""
core/finding_identity.py
Fingerprint determinístico de um finding — identidade histórica que
sobrevive a reimportações, independente do id/uuid gerado pelo parser.

Por que isso existe: core/models.py::Vulnerability.id é um uuid gerado a
cada parse (ver parsers/*.py) — dois imports do mesmo relatório geram dois
ids diferentes para o "mesmo" finding, e core/finding_store.py usaria isso
como identidade só duplicaria tudo a cada reimportação. O fingerprint aqui
é calculado a partir do CONTEÚDO do finding (ferramenta + regra + local +
CVE), não de um valor aleatório — então o mesmo problema, encontrado de
novo num scan posterior, cai no mesmo fingerprint.

Tolerante a campos ausentes: nenhum campo é obrigatório para o cálculo
funcionar (ver testes correspondentes em test_finding_identity.py, se
existir, ou o roteiro manual do PDF de entrega).
"""
import hashlib

from core.models import Vulnerability


def fingerprint(vuln: Vulnerability) -> str:
    """Calcula o fingerprint determinístico de um finding.

    Campos usados, nessa ordem: ferramenta, regra (rule_id — cai para title
    se a ferramenta não informar regra, nunca title sozinho), localização
    (file_path ou url, normalizado), linha e CVE. Cada campo ausente vira
    string vazia — não quebra o cálculo, só reduz a precisão da identidade
    pra aquele finding específico (regra 1 do documento de evolução: "a
    implementação deve ser tolerante quando algum campo não existir").
    """
    tool = (vuln.tool or "").strip().lower()
    rule = (vuln.rule_id or vuln.title or "").strip().lower()
    location = (vuln.file_path or vuln.url or "").strip().lower().replace("\\", "/")
    line = str(vuln.line) if vuln.line else ""
    cve = (vuln.cve_id or "").strip().lower()

    raw = "|".join([tool, rule, location, line, cve])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]
