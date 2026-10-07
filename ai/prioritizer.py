# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
ai/prioritizer.py
Função 2 — Priorização inteligente de vulnerabilidades com contexto de negócio.
"""
import re
from dataclasses import dataclass, field
from ai.provider import LLMProvider
from core.models import Vulnerability, Severity, ScanType
from core.company_context import CompanyContext
from core.asset import Asset
from core import threat_intel

SYSTEM_PROMPT = """Você é um analista sênior de segurança de aplicações (AppSec).
Sua função é priorizar vulnerabilidades para times de desenvolvimento com base em
risco real, exploitabilidade e impacto ao negócio — considerando o contexto
específico da empresa fornecido.
Responda sempre em português brasileiro e em formato JSON válido.
Quando uma vulnerabilidade tiver o campo "asset" preenchido, considere a
exposição daquele ativo específico (internet_facing, critical_asset,
contains_sensitive_data, customer_facing) como fator de risco tão ou mais
importante que a severidade técnica isolada.
Quando "cisa_kev" for true, o CVE está no catálogo CISA KEV: há exploração
ativa confirmada em ataques reais — trate como o fator de urgência mais forte,
acima do CVSS. "epss" é a probabilidade (0 a 1) de exploração nos próximos 30
dias segundo o FIRST EPSS; use-a como indicador de explorabilidade mais
confiável que o CVSS teórico. Campos null significam "sem informação", não
"sem risco"."""

SEV_SCORE  = {Severity.CRITICAL: 40, Severity.HIGH: 25, Severity.MEDIUM: 10, Severity.LOW: 3, Severity.INFO: 0}
TYPE_SCORE = {ScanType.SECRETS: 20, ScanType.DAST: 15, ScanType.SAST: 10, ScanType.SCA: 8}
CVSS_WEIGHT = 2.5

# Inteligência de ameaças (core/threat_intel.py). Pesos heurísticos, na mesma
# escala das outras parcelas: KEV é exploração CONFIRMADA, então vale mais que
# um CVSS 10 inteiro (+25) — um CVE médio que está sendo explorado hoje deve
# passar na frente de um crítico que ninguém explora. EPSS é probabilidade, entra
# proporcional (EPSS 0.9 -> +22.5). Parcelas abaixo de EPSS_MIN_POINTS não são
# exibidas: "+0.1" só polui a composição do score.
KEV_POINTS = 30
KEV_RANSOMWARE_POINTS = 5
EPSS_WEIGHT = 25
EPSS_MIN_POINTS = 0.5


def _intel_of(vuln: Vulnerability) -> "threat_intel.ThreatIntel | None":
    intel = threat_intel.lookup(vuln.cve_id)
    return intel if intel is not None and intel.has_signal else None


def _fmt_date(iso: str) -> str:
    """'2021-12-10' -> '10/12/2021'; qualquer outra coisa volta como veio."""
    parts = iso.split("-")
    return f"{parts[2]}/{parts[1]}/{parts[0]}" if len(parts) == 3 else iso


@dataclass
class ScoreComponent:
    """Uma parcela nomeada do pre_score — permite mostrar o cálculo de forma
    transparente na UI (ex.: 'CVSS: +18.0', 'Setor Financeiro (contexto): +5')."""
    label: str
    value: float


@dataclass
class PrioritizedVuln:
    vuln: Vulnerability
    pre_score: float
    ai_rank: int | None
    ai_reason: str
    final_score: float
    score_breakdown: list[ScoreComponent] = field(default_factory=list)
    ai_reason_summary: str = ""   # resumo de 1 linha — mostrado sempre visível na UI,
                                   # com ai_reason (o parágrafo completo) atrás de "ver detalhes"
    # Parcela da IA (0–100) usada nos 30% do score final, ou None quando a IA
    # não participou (sem backend / resposta inválida) — aí final_score ==
    # pre_score. 0.0 = item fora do top N que a IA avaliou. Mostrado no card
    # para o número final bater com a conta (ver PriorityCard).
    ai_weight: float | None = None


_SEV_LABEL_PT = {
    Severity.CRITICAL: "crítica", Severity.HIGH: "alta",
    Severity.MEDIUM: "média", Severity.LOW: "baixa", Severity.INFO: "informativa",
}

_SUMMARY_TYPE_PT = {
    ScanType.SECRETS:   "Segredo exposto",
    ScanType.DAST:       "Falha explorável remotamente",
    ScanType.SAST:       "Falha no código-fonte",
    ScanType.SCA:        "Dependência vulnerável",
    ScanType.CONTAINER:  "Vulnerabilidade na imagem do container",
    ScanType.IAC:        "Infraestrutura mal configurada",
}


def _build_summary_line(vuln: Vulnerability, ctx: CompanyContext | None = None,
                         asset: Asset | None = None) -> str:
    """Resumo de 1 linha pra "bater o olho": o tipo técnico + o único fator de
    negócio/ativo mais forte, se houver. Deliberadamente curto — o raciocínio
    completo continua em _build_fallback_reason()/ai_reason, só que atrás de
    'ver detalhes' na UI."""
    parts = [_SUMMARY_TYPE_PT.get(vuln.scan_type, "Vulnerabilidade identificada")]

    highlight = None
    intel = _intel_of(vuln)
    # Exploração ativa confirmada é o sinal mais forte que existe — tem
    # precedência sobre ativo/contexto no resumo de uma linha.
    if intel and intel.in_kev:
        highlight = "explorada ativamente (CISA KEV)"
        if intel.kev_ransomware:
            highlight += ", usada em ransomware"
    elif intel and intel.epss is not None and intel.epss >= 0.1:
        highlight = f"EPSS {intel.epss * 100:.0f}% de chance de exploração em 30 dias"
    if highlight is None and asset:
        if asset.internet_facing and asset.critical_asset:
            highlight = f"ativo crítico exposto à internet ({asset.label})"
        elif asset.internet_facing:
            highlight = f"ativo exposto à internet ({asset.label})"
        elif asset.critical_asset:
            highlight = f"ativo crítico ({asset.label})"
        elif asset.contains_sensitive_data:
            highlight = f"ativo com dados sensíveis ({asset.label})"
    if not highlight and ctx and ctx.preenchido:
        if ctx.setor in ("Financeiro", "Saúde", "Governo") and vuln.severity in (Severity.CRITICAL, Severity.HIGH):
            highlight = f"setor {ctx.setor}"
        elif ctx.armazena_pii and "LGPD" in ctx.regulamentacoes and vuln.scan_type == ScanType.SECRETS:
            highlight = "dados pessoais sob LGPD"

    if highlight:
        parts.append(highlight)
    return " — ".join(parts)


def pre_score_breakdown(vuln: Vulnerability, ctx: CompanyContext | None = None,
                         asset: Asset | None = None) -> list[ScoreComponent]:
    """Mesma lógica que antes vivia só dentro de pre_score(), mas agora cada
    parcela é mantida separada e nomeada — é o que a UI usa para mostrar
    'por que essa vulnerabilidade virou prioridade'."""
    components: list[ScoreComponent] = []

    sev_val = SEV_SCORE.get(vuln.severity, 0)
    components.append(ScoreComponent(f"Severidade base ({_SEV_LABEL_PT.get(vuln.severity, vuln.severity.value)})", sev_val))

    type_val = TYPE_SCORE.get(vuln.scan_type, 0)
    if type_val:
        components.append(ScoreComponent(f"Tipo de scan ({vuln.scan_type.value})", type_val))

    if vuln.cvss_score:
        components.append(ScoreComponent(f"CVSS ({vuln.cvss_score})", round(vuln.cvss_score * CVSS_WEIGHT, 1)))

    # Exploração real (CISA KEV) e probabilidade de exploração (EPSS) — só
    # existem para CVEs; ver core/threat_intel.py. Vem do cache local: aqui
    # nunca há chamada de rede.
    intel = _intel_of(vuln)
    if intel:
        if intel.in_kev:
            components.append(ScoreComponent("CISA KEV — exploração ativa confirmada", KEV_POINTS))
            if intel.kev_ransomware:
                components.append(ScoreComponent("KEV: usada em campanhas de ransomware", KEV_RANSOMWARE_POINTS))
        if intel.epss is not None:
            epss_pts = round(intel.epss * EPSS_WEIGHT, 1)
            if epss_pts >= EPSS_MIN_POINTS:
                pct = (f", percentil {intel.epss_percentile * 100:.0f}"
                       if intel.epss_percentile is not None else "")
                components.append(ScoreComponent(f"EPSS {intel.epss * 100:.1f}%{pct}", epss_pts))

    if vuln.scan_type == ScanType.SECRETS:
        components.append(ScoreComponent("Segredo exposto", 15))

    # Ajustes de contexto no pre-score
    if ctx and ctx.preenchido:
        # Confidencialidade alta → secrets e SCA sobem
        if ctx.importancia_confidencialidade >= 8 and vuln.scan_type in (ScanType.SECRETS, ScanType.SCA):
            components.append(ScoreComponent("Confidencialidade prioritária (contexto)", 8))
        # Disponibilidade alta → DAST sobe
        if ctx.importancia_disponibilidade >= 8 and vuln.scan_type == ScanType.DAST:
            components.append(ScoreComponent("Disponibilidade prioritária (contexto)", 8))
        # Setor financeiro/saúde/governo → criticidade geral maior
        if ctx.setor in ("Financeiro", "Saúde", "Governo") and vuln.severity in (Severity.CRITICAL, Severity.HIGH):
            components.append(ScoreComponent(f"Setor {ctx.setor} (contexto)", 5))
        # LGPD/PCI → PII e dados financeiros têm peso maior
        if ctx.armazena_pii and "LGPD" in ctx.regulamentacoes and vuln.scan_type == ScanType.SECRETS:
            components.append(ScoreComponent("PII sob LGPD (contexto)", 5))

    # Ajustes de contexto POR ATIVO — mais específico que o contexto global da
    # empresa: reflete a exposição real do sistema onde essa vulnerabilidade
    # foi encontrada, não a empresa como um todo.
    if asset:
        if asset.internet_facing:
            components.append(ScoreComponent(f"Ativo internet-facing ({asset.label})", 10))
        if asset.critical_asset:
            components.append(ScoreComponent(f"Ativo crítico ({asset.label})", 8))
        if asset.contains_sensitive_data and vuln.scan_type in (ScanType.SECRETS, ScanType.SCA, ScanType.DAST):
            components.append(ScoreComponent(f"Ativo com dados sensíveis ({asset.label})", 8))
        if asset.customer_facing and vuln.severity in (Severity.CRITICAL, Severity.HIGH):
            components.append(ScoreComponent(f"Ativo customer-facing ({asset.label})", 5))

    return components


def pre_score(vuln: Vulnerability, ctx: CompanyContext | None = None,
              asset: Asset | None = None) -> float:
    """Score determinístico — ajustado pelo contexto da empresa e do ativo quando
    disponíveis. Soma as parcelas de pre_score_breakdown() e aplica o teto de 100."""
    total = sum(c.value for c in pre_score_breakdown(vuln, ctx, asset))
    return min(total, 100.0)


_TYPE_DESCRIPTION = {
    ScanType.SECRETS: "um segredo exposto no código ou repositório",
    ScanType.DAST: "uma falha explorável remotamente, direto pela aplicação em execução",
    ScanType.SAST: "uma falha identificada diretamente no código-fonte",
    ScanType.SCA: "uma dependência de terceiros com vulnerabilidade conhecida",
    ScanType.CONTAINER: "uma vulnerabilidade em pacote do sistema operacional dentro de uma imagem de container",
    ScanType.IAC: "uma má configuração em arquivo de infraestrutura como código (Dockerfile, Kubernetes, Terraform)",
}

_TYPE_RISK = {
    ScanType.SECRETS: "Segredos expostos dão acesso direto a sistemas e dados sem precisar explorar nenhuma outra falha, o que os torna fáceis de abusar assim que alguém os encontra.",
    ScanType.DAST: "Por ser explorável remotamente, um invasor pode tentar essa falha direto pela internet, sem precisar de acesso prévio ao ambiente.",
    ScanType.SAST: "Por estar no código-fonte, esse tipo de falha costuma se repetir em outros pontos do sistema que seguem o mesmo padrão, o que amplia o impacto real.",
    ScanType.SCA: "Dependências vulneráveis costumam ter exploits públicos já documentados, o que reduz bastante o esforço necessário para um ataque.",
    ScanType.CONTAINER: "Uma imagem vulnerável se propaga para todo container criado a partir dela, então o impacto tende a se repetir em cada ambiente onde essa imagem for implantada.",
    ScanType.IAC: "Más configurações de infraestrutura costumam abrir uma porta de entrada estrutural (ex.: privilégios excessivos, rede exposta) que facilita ou amplia outros ataques.",
}

_URGENCY_BY_SEVERITY = {
    Severity.CRITICAL: "Recomenda-se correção imediata, antes de qualquer outra tarefa de desenvolvimento.",
    Severity.HIGH: "Recomenda-se corrigir na próxima janela de deploy disponível.",
    Severity.MEDIUM: "Pode entrar no planejamento normal da sprint, sem precisar de correção emergencial.",
    Severity.LOW: "Baixa urgência — pode ficar no backlog de melhorias técnicas.",
    Severity.INFO: "Caráter informativo — avaliar se vale a pena corrigir junto de outras tarefas do mesmo módulo.",
}


def _build_fallback_reason(vuln: Vulnerability, ctx: CompanyContext | None, in_top: bool,
                            asset: Asset | None = None) -> str:
    """Monta uma justificativa em várias frases, com o raciocínio por trás do
    score (fator técnico + risco + contexto de negócio + ativo + recomendação).
    Usada quando a IA não está disponível (ou o item não veio na resposta do LLM)."""
    sev_label = {
        Severity.CRITICAL: "severidade crítica", Severity.HIGH: "severidade alta",
        Severity.MEDIUM: "severidade média", Severity.LOW: "severidade baixa",
        Severity.INFO: "severidade informativa",
    }.get(vuln.severity, "severidade não classificada")
    tipo_desc = _TYPE_DESCRIPTION.get(vuln.scan_type, "uma vulnerabilidade identificada na aplicação")

    frase1 = f"Vulnerabilidade de {sev_label}: trata-se de {tipo_desc}"
    if vuln.cvss_score:
        frase1 += f", com CVSS {vuln.cvss_score}"
    frase1 += "."

    frases = [frase1]

    risco = _TYPE_RISK.get(vuln.scan_type)
    if risco:
        frases.append(risco)

    intel = _intel_of(vuln)
    if intel and intel.in_kev:
        desde = f" desde {_fmt_date(intel.kev_date_added)}" if intel.kev_date_added else ""
        frase = (f"O {intel.cve} consta no catálogo CISA KEV{desde}: há exploração ativa "
                 "confirmada em ataques reais, o que pesa mais que a nota teórica do CVSS")
        if intel.kev_ransomware:
            frase += " — e ele já foi usado em campanhas de ransomware"
        frases.append(frase + ".")
    if intel and intel.epss is not None:
        pct = (f" (mais alta que {intel.epss_percentile * 100:.0f}% dos CVEs avaliados)"
               if intel.epss_percentile is not None else "")
        frases.append(f"O EPSS estima {intel.epss * 100:.1f}% de probabilidade de exploração "
                      f"nos próximos 30 dias{pct}.")

    motivos_negocio = []
    if ctx and ctx.preenchido:
        if ctx.importancia_confidencialidade >= 8 and vuln.scan_type in (ScanType.SECRETS, ScanType.SCA):
            motivos_negocio.append("a empresa declarou confidencialidade dos dados como prioridade alta")
        if ctx.importancia_disponibilidade >= 8 and vuln.scan_type == ScanType.DAST:
            motivos_negocio.append("a empresa declarou disponibilidade dos sistemas como prioridade alta")
        if ctx.setor in ("Financeiro", "Saúde", "Governo") and vuln.severity in (Severity.CRITICAL, Severity.HIGH):
            motivos_negocio.append(f"o setor {ctx.setor} costuma ter exigências regulatórias e reputacionais mais rígidas")
        if ctx.armazena_pii and "LGPD" in ctx.regulamentacoes and vuln.scan_type == ScanType.SECRETS:
            motivos_negocio.append("há dados pessoais em jogo sob LGPD, o que aumenta o risco legal de um vazamento")
    if motivos_negocio:
        frases.append("No contexto informado da empresa, " + "; ".join(motivos_negocio) + ".")

    motivos_ativo = []
    if asset:
        if asset.internet_facing:
            motivos_ativo.append(f"o ativo \"{asset.label}\" está exposto à internet")
        if asset.critical_asset:
            motivos_ativo.append("é um ativo marcado como crítico para a operação")
        if asset.contains_sensitive_data:
            motivos_ativo.append("esse ativo armazena ou processa dados sensíveis")
        if asset.customer_facing:
            motivos_ativo.append("é um ativo diretamente acessado por clientes")
    if motivos_ativo:
        frases.append("Sobre o ativo afetado: " + "; ".join(motivos_ativo) + ".")

    if in_top and intel and intel.in_kev:
        frases.append("Por estar sob exploração ativa, recomenda-se correção imediata, "
                      "independentemente da severidade declarada pela ferramenta.")
    elif in_top:
        frases.append(_URGENCY_BY_SEVERITY.get(vuln.severity, ""))
    else:
        frases.append("Não entrou entre os itens de prioridade máxima analisados pela IA nesta rodada, mas ainda deve ser corrigida dentro do ciclo normal de desenvolvimento.")

    return " ".join(f for f in frases if f)


def prioritize(
    vulns: list[Vulnerability],
    provider: LLMProvider,
    ctx: CompanyContext | None = None,
    assets: dict[str, Asset] | None = None,
    top_n: int = 10,
) -> list[PrioritizedVuln]:
    if not vulns:
        return []
    assets = assets or {}

    def _asset_of(v: Vulnerability) -> Asset | None:
        return assets.get(v.asset_id) if v.asset_id else None

    # Calcula o breakdown uma única vez por vuln — pre_score() deriva o total
    # da mesma lista, então não duplicamos a lógica de pontuação.
    breakdowns = {v.id: pre_score_breakdown(v, ctx, _asset_of(v)) for v in vulns}
    scored = [(v, min(sum(c.value for c in breakdowns[v.id]), 100.0)) for v in vulns]
    scored.sort(key=lambda x: x[1], reverse=True)

    top  = scored[:top_n]
    rest = scored[top_n:]

    ai_results: dict[str, tuple[int, str]] = {}
    if provider.available:
        ai_results = _llm_rerank(top, provider, ctx, assets)

    # A combinação 70% técnico / 30% IA só entra quando a IA respondeu de
    # verdade. Antes ela entrava sempre, com o rank "padrão" = posição no
    # score técnico: sem IA nenhuma, achados idênticos saíam com notas
    # diferentes só pela ordem, e o card ainda exibia "IA rank #N".
    llm_used = bool(ai_results)
    n_top = len(top)

    result: list[PrioritizedVuln] = []
    for i, (vuln, ps) in enumerate(top):
        asset = _asset_of(vuln)
        fallback_reason = _build_fallback_reason(vuln, ctx, in_top=True, asset=asset)
        summary = _build_summary_line(vuln, ctx, asset)
        if llm_used:
            ai_rank, ai_reason = ai_results.get(vuln.id, (None, ""))
            # Item que a IA não devolveu mantém a própria posição técnica
            # (não é punido por uma omissão do modelo), mas sem "IA rank".
            position = ai_rank if ai_rank is not None else i + 1
            ai_weight = (n_top - position + 1) / n_top * 100
            final = min(round(ps * 0.7 + ai_weight * 0.3, 1), 100.0)
            reason = ai_reason or fallback_reason
        else:
            ai_rank, ai_weight, final, reason = None, None, ps, fallback_reason
        result.append(PrioritizedVuln(vuln=vuln, pre_score=ps, ai_rank=ai_rank,
                                      ai_reason=reason, final_score=final,
                                      score_breakdown=breakdowns[vuln.id],
                                      ai_reason_summary=summary, ai_weight=ai_weight))

    for vuln, ps in rest:
        asset = _asset_of(vuln)
        reason = _build_fallback_reason(vuln, ctx, in_top=False, asset=asset)
        summary = _build_summary_line(vuln, ctx, asset)
        # Fora do top N a IA não avaliou: parcela da IA = 0 (mesma fórmula).
        # Antes esses itens ficavam com o score técnico cheio enquanto os do
        # top eram "diluídos" em 70/30 — um item em 11º podia aparecer acima
        # do 6º. Com parcela 0 isso não acontece: todo item do top tem score
        # técnico >= e parcela da IA > 0, então fica sempre acima.
        if llm_used:
            ai_weight, final = 0.0, round(ps * 0.7, 1)
        else:
            ai_weight, final = None, ps
        result.append(PrioritizedVuln(vuln=vuln, pre_score=ps, ai_rank=None,
                                      ai_reason=reason, final_score=final,
                                      score_breakdown=breakdowns[vuln.id],
                                      ai_reason_summary=summary, ai_weight=ai_weight))

    result.sort(key=lambda x: x.final_score, reverse=True)
    return result


_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def _extract_ranking(text: str) -> list:
    """Tira a lista "ranking" da resposta do modelo, tolerando o que modelos
    reais costumam mandar em volta do JSON: bloco <think>...</think> de
    modelos de raciocínio, cerca ```json / ```JSON, frase antes ("Aqui está:").
    Antes só um prefixo exato "```json" era removido e qualquer variação
    fazia a reordenação da IA ser descartada em silêncio."""
    import json
    text = _THINK_BLOCK.sub("", text or "")
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        data = json.loads(text[start:end + 1])
        if isinstance(data, dict):
            ranking = data.get("ranking")
            if isinstance(ranking, list):
                return ranking
    # Alguns modelos devolvem direto a lista, sem o objeto em volta.
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        data = json.loads(text[start:end + 1])
        if isinstance(data, list):
            return data
    raise ValueError("resposta da IA sem um ranking em JSON")


def _parse_ranking(ranking: list, scored: list[tuple[Vulnerability, float]]) -> dict[str, tuple[int, str]]:
    """Converte a lista do modelo em {vuln.id: (rank, reason)}, item a item —
    um item malformado é ignorado sozinho em vez de derrubar a resposta
    inteira (antes, um "rank": "1" em texto quebrava a Priorização toda)."""
    index_to_id = {i: v.id for i, (v, _) in enumerate(scored)}
    known_ids = set(index_to_id.values())
    n = len(scored)
    out: dict[str, tuple[int, str]] = {}
    for item in ranking:
        if not isinstance(item, dict):
            continue
        # O modelo identifica cada item pelo "index" (0..n-1) — o UUID de 36
        # caracteres também é aceito, mas modelos pequenos erram ao copiá-lo.
        vid = item.get("id") if item.get("id") in known_ids else None
        if vid is None:
            try:
                vid = index_to_id.get(int(item.get("index")))
            except (TypeError, ValueError):
                vid = None
        if vid is None or vid in out:
            continue
        try:
            rank = int(float(item.get("rank")))
        except (TypeError, ValueError):
            continue
        rank = max(1, min(rank, n))   # "rank": 0 ou 99 não podem estourar a escala
        out[vid] = (rank, str(item.get("reason") or "").strip())
    return out


def _llm_rerank(
    scored: list[tuple[Vulnerability, float]],
    provider: LLMProvider,
    ctx: CompanyContext | None = None,
    assets: dict[str, Asset] | None = None,
) -> dict[str, tuple[int, str]]:
    import json
    assets = assets or {}

    vuln_list = []
    for i, (v, ps) in enumerate(scored):
        asset = assets.get(v.asset_id) if v.asset_id else None
        intel = threat_intel.lookup(v.cve_id)   # None quando não é CVE
        vuln_list.append({
            "index": i,
            "title": v.title,
            "severity": v.severity.value,
            "type": v.scan_type.value,
            "tool": v.tool,
            "file": v.file_path or v.url or "",
            "cve": v.cve_id or "",
            "cvss": v.cvss_score,
            "cisa_kev": intel.in_kev if intel else None,
            "kev_ransomware": (intel.kev_ransomware if intel and intel.in_kev else None),
            "epss": (round(intel.epss, 4) if intel and intel.epss is not None else None),
            "epss_percentile": (round(intel.epss_percentile, 4)
                                if intel and intel.epss_percentile is not None else None),
            "pre_score": ps,
            "asset": ({
                "name": asset.label,
                "environment": asset.environment,
                "internet_facing": asset.internet_facing,
                "critical_asset": asset.critical_asset,
                "contains_sensitive_data": asset.contains_sensitive_data,
                "customer_facing": asset.customer_facing,
            } if asset else None),
        })

    # Injeta contexto da empresa no prompt se disponível
    context_block = ""
    if ctx and ctx.preenchido:
        context_block = f"""
{ctx.to_prompt_text()}

Com base nesse contexto empresarial, considere:
- Vulnerabilidades em sistemas de missão crítica têm peso maior
- O setor {ctx.setor} tem requisitos regulatórios específicos
- Disponibilidade ({ctx.importancia_disponibilidade}/10), Confidencialidade ({ctx.importancia_confidencialidade}/10) e Integridade ({ctx.importancia_integridade}/10) são as prioridades declaradas
- Prefira corrigir primeiro o que impacta diretamente os sistemas que geram receita
"""
    else:
        context_block = "\n(Contexto da empresa não configurado — usando critérios técnicos padrão)\n"

    prompt = f"""Você recebeu vulnerabilidades detectadas em uma aplicação.
Re-ordene-as da mais urgente para a menos urgente considerando o contexto abaixo.
{context_block}
Vulnerabilidades:
{json.dumps(vuln_list, ensure_ascii=False, indent=2)}

Responda APENAS com JSON válido, sem texto antes ou depois. Inclua TODAS as
{len(vuln_list)} vulnerabilidades, cada uma uma única vez, identificada pelo
mesmo "index" da lista acima; "rank" é um número inteiro de 1 a {len(vuln_list)}:
{{
  "ranking": [
    {{
      "index": 0,
      "rank": 1,
      "reason": "Explique em 2 a 4 frases o raciocínio por trás dessa posição: (1) o principal fator técnico (severidade, tipo de falha, CVSS — e, quando presentes, CISA KEV e EPSS, que indicam exploração real), (2) por que isso é ou não fácil de explorar / qual o risco concreto, (3) se o contexto da empresa foi informado, cite o motivo de negócio específico que pesou na decisão, e (4) uma recomendação objetiva de urgência (ex: corrigir imediatamente, próxima sprint, backlog)."
    }}
  ]
}}"""

    try:
        response = provider.chat(prompt, system=SYSTEM_PROMPT, timeout=90)
        return _parse_ranking(_extract_ranking(response.text), scored)
    except Exception as e:
        # Sem IA utilizável: prioritize() cai no score técnico puro (sem
        # 70/30 e sem "IA rank" nos cards), em vez de travar a tela.
        print(f"[prioritizer] LLM rerank falhou: {e}")
        return {}

