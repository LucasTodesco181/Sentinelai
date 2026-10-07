# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
core/coverage.py
Responde a uma pergunta que o score sozinho não responde: "este tipo de
scan chegou a ser executado?"

Por que isso existe
-------------------
O scorer devolve 0 para um tipo de scan sem nenhuma vulnerabilidade aberta.
Só que 0 pode significar duas coisas MUITO diferentes:

    a) "rodei DAST e não encontrei nada"        -> ótima notícia
    b) "nunca rodei DAST"                       -> nenhuma notícia

Antes deste módulo, o Dashboard pintava as duas situações do mesmo jeito:
anel verde com 0. Ou seja, a ASPM afirmava cobertura que não tinha — o
pior tipo de erro numa ferramenta de postura de segurança, porque
tranquiliza sem base.

Como a cobertura é inferida
---------------------------
Pelas FERRAMENTAS cujos relatórios foram importados, não pelos achados.
Se o Trivy rodou e não achou nenhuma má configuração de IaC, IaC continua
coberto (e com risco 0 de verdade) — inferir pelos achados faria esse caso
voltar a parecer "não escaneado".
"""
from core.models import ScanReport, ScanType

#: O que cada ferramenta é capaz de cobrir. Uma ferramenta que rodou cobre
#: TODOS os tipos desta lista, mesmo que não tenha achado nada em algum
#: deles — foi justamente isso que ela foi lá verificar.
TOOL_SCAN_TYPES: dict[str, set[str]] = {
    "semgrep":  {"SAST"},
    "zap":      {"DAST"},
    "snyk":     {"SCA"},
    "gitleaks": {"SECRETS"},
    # O Trivy é multi-estágio: uma execução cobre IaC e segredos sempre, e
    # o terceiro tipo depende do MODO (ver parsers/trivy_parser.py, campo
    # ArtifactType do relatório):
    #   - "trivy"       -> scan de pasta (modo fs, o único que o próprio app
    #                      dispara): CVE em package.json/pom.xml/... = SCA.
    #   - "trivy-image" -> relatório de imagem Docker importado: Container.
    # Antes o Trivy marcava os DOIS sempre, e um simples "Escanear Pasta"
    # deixava o anel Container verde ("verificado, risco 0") sem nenhuma
    # imagem ter sido escaneada — exatamente a falsa segurança que este
    # módulo existe para evitar. A chave certa de cada relatório vem de
    # coverage_key() abaixo.
    "trivy":       {"SCA", "IAC", "SECRETS"},
    "trivy-image": {"CONTAINER", "IAC", "SECRETS"},
    "grype":       {"SCA"},
}


def coverage_key(report: ScanReport) -> str:
    """Nome usado para a cobertura (e gravado no histórico de scans).

    Igual a report.tool, exceto no Trivy de imagem, que cobre tipos
    diferentes do Trivy de pasta (ver TOOL_SCAN_TYPES). O histórico
    (core/scan_history.py) só é usado para cobertura, então gravar
    "trivy-image" lá não aparece em nenhuma tela."""
    if report.tool == "trivy" and report.scan_type == ScanType.CONTAINER:
        return "trivy-image"
    return report.tool


def covered_scan_types_from_tools(tools: set[str]) -> set[str]:
    """Mesma lógica de covered_scan_types(), mas a partir de um conjunto de
    nomes de ferramenta em vez de ScanReport completos — usado para somar a
    cobertura persistida (core/scan_history.py) à cobertura da sessão atual,
    já que core.aggregator.reports some da memória a cada reinício do app."""
    covered: set[str] = set()
    for tool in tools:
        covered |= TOOL_SCAN_TYPES.get(tool, set())
    return covered


def covered_scan_types(reports: list[ScanReport]) -> set[str]:
    """Tipos de scan efetivamente cobertos pelos relatórios importados.

    Conjunto vazio = nada foi importado ainda (o Dashboard usa isso para
    mostrar o estado inicial em vez de um painel de zeros)."""
    covered = covered_scan_types_from_tools({coverage_key(r) for r in reports})
    for report in reports:
        # Ferramenta desconhecida (parser novo que ainda não está no mapa):
        # cai no tipo declarado pelo próprio relatório, para não sumir da tela.
        if coverage_key(report) not in TOOL_SCAN_TYPES:
            covered.add(report.scan_type.value)
    return covered


def uncovered_scan_types(reports: list[ScanReport], known: list[str]) -> list[str]:
    """Tipos que aparecem na UI mas que ninguém escaneou — usado para dizer
    ao usuário o que ainda falta, em vez de deixar o vazio passar por 'ok'."""
    covered = covered_scan_types(reports)
    return [t for t in known if t not in covered]
