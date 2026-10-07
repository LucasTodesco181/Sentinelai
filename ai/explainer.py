"""
ai/explainer.py
Função 1 — Explicar vulnerabilidades em linguagem simples.

Recebe uma Vulnerability e retorna uma explicação estruturada
em português, sem jargão técnico excessivo.
"""
from ai.provider import LLMProvider, LLMResponse
from core.models import Vulnerability, Severity
from core.company_context import CompanyContext
from core.asset import Asset
from core import threat_intel

# Severidade em pt-br no prompt — antes ia "CRITICAL"/"HIGH", e a resposta
# da IA repetia os termos em inglês no meio do texto em português (P2 #13).
_SEV_PT = {
    "critical": "CRÍTICA", "high": "ALTA", "medium": "MÉDIA", "low": "BAIXA", "info": "INFORMATIVA",
}


def _sev(value: str) -> str:
    return _SEV_PT.get(value, value.upper())


SYSTEM_PROMPT = """Você é um especialista em cibersegurança que explica vulnerabilidades
para times de desenvolvimento. Seja claro, direto e prático.
Sempre responda em português brasileiro.
Nunca invente CVEs ou referências que não foram fornecidas."""


def _business_context_block(ctx: CompanyContext | None = None,
                             asset: Asset | None = None) -> str:
    """
    Monta um bloco de texto com o contexto de negócio relevante (empresa +
    ativo) para injetar no prompt — mesma ideia usada em ai/prioritizer.py
    para a Priorização IA, aqui aplicada também à explicação individual e ao
    resumo executivo, que antes ignoravam esse contexto por completo mesmo
    quando preenchido.
    """
    lines: list[str] = []

    if ctx and ctx.preenchido:
        if ctx.setor:
            porte = f", porte {ctx.porte}" if ctx.porte else ""
            lines.append(f"Setor da empresa: {ctx.setor}{porte}.")
        prioridades = []
        if ctx.importancia_confidencialidade >= 8:
            prioridades.append("confidencialidade dos dados é prioridade alta")
        if ctx.importancia_disponibilidade >= 8:
            prioridades.append("disponibilidade dos sistemas é prioridade alta")
        if prioridades:
            lines.append("Prioridades de negócio: " + "; ".join(prioridades) + ".")
        if ctx.armazena_pii and "LGPD" in ctx.regulamentacoes:
            lines.append("A empresa armazena dados pessoais e precisa atender à LGPD.")
        if ctx.processa_financeiro and "PCI-DSS" in ctx.regulamentacoes:
            lines.append("A empresa processa dados financeiros e precisa atender ao PCI-DSS.")

    if asset:
        atributos = []
        if asset.internet_facing:
            atributos.append("exposto à internet")
        if asset.critical_asset:
            atributos.append("crítico para a operação")
        if asset.contains_sensitive_data:
            atributos.append("armazena dados sensíveis")
        if asset.customer_facing:
            atributos.append("acessado diretamente por clientes")
        if atributos:
            lines.append(f'Ativo afetado: "{asset.label}" ({", ".join(atributos)}).')
        else:
            lines.append(f'Ativo afetado: "{asset.label}".')

    if not lines:
        return ""

    return "CONTEXTO DE NEGÓCIO:\n" + "\n".join(lines)


def explain_vulnerability(vuln: Vulnerability, provider: LLMProvider,
                           ctx: CompanyContext | None = None,
                           asset: Asset | None = None) -> LLMResponse:
    """
    Gera uma explicação em linguagem simples para uma vulnerabilidade.
    Retorna LLMResponse com o texto gerado.

    `ctx`/`asset` são opcionais — quando informados (contexto da empresa
    preenchido e/ou a vulnerabilidade vinculada a um ativo cadastrado), a
    explicação passa a considerar o impacto real pro negócio, não só a
    gravidade técnica.
    """
    # Trunca campos longos para evitar estouro de token limit no Groq free tier
    def _trunc(text: str, limit: int = 300) -> str:
        return text[:limit] + "..." if len(text) > limit else text

    context_parts = [
        f"Título: {vuln.title}",
        f"Ferramenta: {vuln.tool.upper()} ({vuln.scan_type.value})",
        f"Severidade: {_sev(vuln.severity.value)}",
    ]
    if vuln.rule_id and vuln.rule_id != vuln.title:
        context_parts.append(f"Regra: {vuln.rule_id}")
    if vuln.file_path:
        context_parts.append(f"Arquivo: {vuln.file_path}")
    if vuln.line:
        context_parts.append(f"Linha: {vuln.line}")
    if vuln.url:
        context_parts.append(f"URL: {_trunc(vuln.url, 100)}")
    if vuln.cve_id:
        context_parts.append(f"CVE: {vuln.cve_id}")
    if vuln.cvss_score:
        context_parts.append(f"CVSS: {vuln.cvss_score}")
    # Exploração real (core/threat_intel.py) — só existe para CVEs, vem do cache.
    intel = threat_intel.lookup(vuln.cve_id)
    if intel and intel.in_kev:
        extra = ", usada em campanhas de ransomware" if intel.kev_ransomware else ""
        context_parts.append(
            f"CISA KEV: SIM — exploração ativa confirmada em ataques reais"
            f" (no catálogo desde {intel.kev_date_added or 'data não informada'}{extra})")
    if intel and intel.epss is not None:
        context_parts.append(
            f"EPSS: {intel.epss * 100:.1f}% de probabilidade de exploração nos próximos 30 dias")
    if vuln.description:
        context_parts.append(f"Descrição: {_trunc(vuln.description, 400)}")
    if vuln.remediation:
        context_parts.append(f"Remediação sugerida: {_trunc(vuln.remediation, 200)}")

    context = "\n".join(context_parts)
    business = _business_context_block(ctx, asset)
    business_block = f"\n\n{business}" if business else ""
    business_instruction = (
        "\n\nLeve o contexto de negócio em conta ao explicar o impacto e definir a "
        "prioridade — não só a gravidade técnica isolada." if business else ""
    )

    prompt = f"""Analise esta vulnerabilidade e responda em 4 seções curtas:

{context}{business_block}

**O QUE É**
[2 frases simples explicando a vulnerabilidade]

**POR QUE É PERIGOSA**
[2 frases sobre o impacto real para o sistema]

**COMO CORRIGIR**
[3 passos práticos de correção]

**PRIORIDADE**
[Uma frase: imediata / 7 dias / próximo ciclo, e por quê]{business_instruction}"""

    return provider.chat(prompt, system=SYSTEM_PROMPT)


def explain_batch_summary(vulns: list[Vulnerability], provider: LLMProvider,
                           ctx: CompanyContext | None = None,
                           assets: dict[str, Asset] | None = None) -> LLMResponse:
    """
    Gera um resumo executivo de um conjunto de vulnerabilidades.
    Útil para relatórios e apresentações.

    `ctx`/`assets` são opcionais — quando informados, o resumo passa a citar
    o setor da empresa e quais ativos críticos/expostos concentram os
    achados mais graves, em vez de só números técnicos agregados.
    """
    from collections import Counter
    assets = assets or {}
    sev_counts = Counter(_sev(v.severity.value) for v in vulns)
    tool_counts = Counter(v.tool for v in vulns)

    top_vulns = sorted(vulns, key=lambda v: ["critical","high","medium","low","info"].index(v.severity.value))[:5]
    top_list = "\n".join(f"- [{_sev(v.severity.value)}] {v.title} ({v.tool})" for v in top_vulns)

    business = _business_context_block(ctx, None)

    # Ativos críticos/expostos com pelo menos um finding crítico ou alto —
    # é o que mais importa destacar num resumo pra gestão, não a lista toda.
    at_risk_assets: dict[str, str] = {}
    for v in vulns:
        if v.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue
        asset = assets.get(v.asset_id) if v.asset_id else None
        if not asset or asset.label in at_risk_assets:
            continue
        atributos = []
        if asset.internet_facing:
            atributos.append("exposto à internet")
        if asset.critical_asset:
            atributos.append("crítico para a operação")
        if atributos:
            at_risk_assets[asset.label] = f'"{asset.label}" ({", ".join(atributos)})'

    if at_risk_assets:
        business += ("\n" if business else "CONTEXTO DE NEGÓCIO:\n")
        business += "Ativos de maior risco: " + ", ".join(at_risk_assets.values()) + "."

    business_block = f"\n\n{business}" if business else ""
    business_instruction = (
        "\n\nRelacione os riscos ao contexto de negócio informado (setor, ativos afetados) "
        "em vez de falar só em termos técnicos genéricos." if business else ""
    )

    prompt = f"""Gere um resumo executivo de segurança com base nos dados abaixo.
Escreva em português para um gestor não técnico entender.

DADOS DO SCAN:
Total de vulnerabilidades: {len(vulns)}
Por severidade: {dict(sev_counts)}
Por ferramenta: {dict(tool_counts)}

Top 5 vulnerabilidades mais críticas:
{top_list}{business_block}

Responda em 3 parágrafos curtos:
1. Situação atual (como está a postura de segurança)
2. Principais riscos identificados
3. Recomendações prioritárias de ação{business_instruction}"""

    return provider.chat(prompt, system=SYSTEM_PROMPT)
