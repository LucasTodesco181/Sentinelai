# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
core/attack_path.py
Attack Path simplificado — cadeias de risco em 3 elos:

    🌐 EXPOSIÇÃO  →  🔓 VULNERABILIDADE  →  💥 IMPACTO

ESCOPO E LIMITAÇÕES (importante para não superestimar o que isso faz):
Isto NÃO é um attack path de verdade como o de ASPMs comerciais (Wiz, Palo
Alto), que constroem grafos reais de infraestrutura a partir de topologia de
rede, permissões IAM e telemetria de runtime. Aqui não existe nenhuma dessas
fontes de dado.

O que existe é uma correlação determinística entre:
  - dados que as ferramentas já reportaram (tipo de scan, severidade, módulo)
  - o contexto declarado do Ativo (core/asset.py), preenchido manualmente

Ou seja: cada "caminho" é uma inferência baseada em regras explícitas, não uma
rota de ataque observada ou validada. Serve para dar leitura de risco
combinado — "esses dois achados juntos, neste ativo, são piores que separados"
— e não deve ser apresentado como prova de explorabilidade real.
"""
import re
from dataclasses import dataclass, field
from collections import defaultdict
from urllib.parse import urlparse

from core.models import Vulnerability, Severity, ScanType
from core.asset import Asset

# Severidade da cadeia (não da vulnerabilidade isolada)
CHAIN_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


@dataclass
class AttackPath:
    """Uma cadeia de risco de 3 elos."""
    rule_id: str                              # qual regra gerou (A, B, C, D)
    severity: str                             # critical | high | medium
    exposure: str                             # elo 1 — como se chega
    vulnerability: str                        # elo 2 — o que se explora
    impact: str                               # elo 3 — o que se consegue
    explanation: str                          # por que isso é um caminho
    asset_name: str | None = None             # ativo envolvido, se houver
    vulns: list[Vulnerability] = field(default_factory=list)  # achados que compõem a cadeia


# ── Vínculo rota (DAST) ↔ arquivo de código (SAST/SCA) — usado pela Regra A ──
#
# Antes as duas pontas eram agrupadas pelos 2 primeiros pedaços do caminho,
# o que nunca casava: a URL do ZAP virava "http:/" e o arquivo do Semgrep
# "routes/login.ts" (ou "C:/Users" num caminho absoluto do Windows). Rota e
# arquivo não têm pasta em comum; o que eles têm em comum é o NOME do recurso
# (/rest/products/search <-> routes/search.ts). A ligação é por esse nome,
# ignorando termos genéricos demais para significar alguma coisa.

_GENERIC_TOKENS = {
    "api", "rest", "graphql", "v1", "v2", "v3", "src", "app", "apps", "lib", "libs",
    "route", "routes", "router", "controller", "controllers", "handler", "handlers",
    "model", "models", "view", "views", "page", "pages", "component", "components",
    "public", "static", "asset", "assets", "index", "main", "server", "client",
    "frontend", "backend", "service", "services", "util", "utils", "helper", "helpers",
    "common", "core", "config", "test", "tests", "spec", "dist", "build", "vendor",
    "www", "html", "htm", "php", "aspx", "jsp", "json", "xml", "package", "lock",
    "pom", "requirements", "polyfill", "runtime", "style", "styles", "favicon",
    "robots", "sitemap", "socket", "http", "https", "localhost",
}
_TOKEN_SPLIT = re.compile(r"[/\\\-_.\s%?=&:]+")


def _tokens(text: str) -> set[str]:
    out: set[str] = set()
    for tok in _TOKEN_SPLIT.split((text or "").lower()):
        if len(tok) < 3 or tok.isdigit() or tok in _GENERIC_TOKENS:
            continue
        # plural simples ("products" <-> "product"), só em palavras maiores
        if tok.endswith("s") and len(tok) > 4:
            tok = tok[:-1]
        if tok not in _GENERIC_TOKENS:
            out.add(tok)
    return out


def _route_tokens(url: str) -> set[str]:
    """Nomes de recurso de uma rota: só o path, sem host, porta ou query."""
    return _tokens(urlparse(url).path)


def _code_file(v: Vulnerability) -> str:
    """Caminho do arquivo sem o sufixo " (pacote@versão)" dos achados de SCA."""
    return (v.file_path or "").split(" (")[0].replace("\\", "/").rstrip("/")


def _file_tokens(path: str) -> set[str]:
    """Nome de recurso de um arquivo: o nome sem extensão ("login.ts" -> login)."""
    name = path.rsplit("/", 1)[-1]
    return _tokens(name.split(".")[0])


def _short_path(path: str) -> str:
    """Últimos 2 pedaços do caminho ("routes/login.ts") — legível no card."""
    parts = [p for p in path.split("/") if p]
    return "/".join(parts[-2:]) if parts else path


# ── Área do projeto — usada pela Regra C quando o achado não tem ativo ──────

_ROOT_AREA = "raiz do projeto"


def _areas(vulns: list[Vulnerability]) -> dict[str, str]:
    """{vuln.id: área}, onde área = primeira pasta a partir da raiz do projeto.

    Semgrep/Gitleaks costumam reportar caminho ABSOLUTO e o Trivy, relativo à
    pasta escaneada. Os absolutos são relativizados pela raiz comum a todos
    eles — sem isso qualquer arquivo no Windows caía na "área" C:/Users e a
    regra ligava segredo e má configuração de pastas sem relação nenhuma."""
    def is_abs(p: str) -> bool:
        return p.startswith("/") or bool(re.match(r"^[A-Za-z]:/", p))

    files = {v.id: _code_file(v) for v in vulns if v.file_path}
    abs_dirs = [p.split("/")[:-1] for p in files.values() if is_abs(p)]
    root: list[str] = []
    if abs_dirs:
        root = abs_dirs[0]
        for d in abs_dirs[1:]:
            n = 0
            while n < min(len(root), len(d)) and root[n].lower() == d[n].lower():
                n += 1
            root = root[:n]

    out: dict[str, str] = {}
    for vid, path in files.items():
        parts = [p for p in path.split("/") if p]
        if is_abs(path):
            parts = [p for p in path.split("/")[len(root):] if p]
        dirs = parts[:-1]
        out[vid] = dirs[0] if dirs else _ROOT_AREA
    return out


def _worst_severity(vulns: list[Vulnerability]) -> str:
    for sev in ("critical", "high", "medium", "low", "info"):
        if any(v.severity.value == sev for v in vulns):
            return sev
    return "info"


def detect(vulns: list[Vulnerability],
           assets: dict[str, Asset] | None = None) -> list[AttackPath]:
    """Detecta caminhos de ataque. Totalmente determinístico — não depende de IA.
    Considera apenas vulnerabilidades em aberto (corrigidas/aceitas não formam
    caminho de risco ativo)."""
    assets = assets or {}
    vulns = [v for v in vulns if v.status.value == "open"]
    if not vulns:
        return []

    paths: list[AttackPath] = []
    paths.extend(_rule_a_dast_confirms_code(vulns))
    paths.extend(_rule_b_exposed_asset_secret(vulns, assets))
    paths.extend(_rule_c_iac_plus_secret(vulns, assets))
    paths.extend(_rule_d_critical_asset_sensitive(vulns, assets))

    paths.sort(key=lambda p: CHAIN_SEVERITY_ORDER.get(p.severity, 9))
    return paths


# ── Regra A: DAST + SAST/SCA no mesmo módulo ────────────────────────────────

def _rule_a_dast_confirms_code(vulns: list[Vulnerability]) -> list[AttackPath]:
    """Se o DAST achou algo numa rota alcançável de fora E existe falha de
    código no arquivo que implementa o mesmo recurso, o caminho de fora até o
    código está evidenciado pelas duas pontas. Um caminho por arquivo."""
    dast = [(v, _route_tokens(v.url)) for v in vulns
            if v.scan_type == ScanType.DAST and v.url]
    if not dast:
        return []

    by_file: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        if v.scan_type in (ScanType.SAST, ScanType.SCA) and v.file_path:
            by_file[_code_file(v)].append(v)

    paths = []
    for path, code in by_file.items():
        ftoks = _file_tokens(path)
        if not ftoks:
            continue
        hits = [(d, toks & ftoks) for d, toks in dast if toks & ftoks]
        if not hits:
            continue
        dast_hits = [d for d, _ in hits]
        shared = sorted(set().union(*(s for _, s in hits)))
        route = urlparse(dast_hits[0].url).path or "/"
        arquivo = _short_path(path)
        envolvidos = dast_hits + code
        worst = _worst_severity(envolvidos)
        paths.append(AttackPath(
            rule_id="A",
            severity=worst if worst in CHAIN_SEVERITY_ORDER else "medium",
            exposure=f"Rota alcançável remotamente ({route[:45]})",
            vulnerability=f"{len(code)} falha(s) de código em {arquivo}",
            impact=f"Comprometimento de {arquivo}",
            explanation=(
                f"O DAST encontrou problema na rota {route}, e o SAST/SCA encontrou falha de "
                f"código em {arquivo} — as duas apontam para o mesmo recurso "
                f"(\"{', '.join(shared)}\"). As duas pontas do caminho, o acesso externo e a "
                f"falha no código, foram evidenciadas por ferramentas diferentes. O vínculo "
                f"rota↔arquivo é inferido pelo nome do recurso, não por rastreamento do código."
            ),
            vulns=envolvidos,
        ))
    return paths


# ── Regra B: ativo internet-facing + segredo exposto ────────────────────────

def _rule_b_exposed_asset_secret(vulns: list[Vulnerability],
                                  assets: dict[str, Asset]) -> list[AttackPath]:
    """Segredo exposto num ativo acessível pela internet: credencial válida +
    porta de entrada aberta."""
    paths = []
    by_asset: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        if v.asset_id:
            by_asset[v.asset_id].append(v)

    for asset_id, asset_vulns in by_asset.items():
        asset = assets.get(asset_id)
        if not asset or not asset.internet_facing:
            continue
        secrets = [v for v in asset_vulns if v.scan_type == ScanType.SECRETS]
        if not secrets:
            continue

        impacto = ("Acesso a dados sensíveis" if asset.contains_sensitive_data
                   else "Acesso não autorizado ao sistema")
        sev = "critical" if asset.contains_sensitive_data else "high"
        paths.append(AttackPath(
            rule_id="B",
            severity=sev,
            exposure=f"Ativo exposto à internet ({asset.label})",
            vulnerability=f"{len(secrets)} segredo(s) exposto(s) no código",
            impact=impacto,
            explanation=(
                f"O ativo \"{asset.label}\" está acessível pela internet e tem credencial exposta "
                f"no código. Um segredo válido dispensa a exploração de qualquer outra falha: "
                f"quem encontrar a credencial entra diretamente."
                + (" Como o ativo processa dados sensíveis, um acesso desses já configura risco de vazamento."
                   if asset.contains_sensitive_data else "")
            ),
            asset_name=asset.label,
            vulns=secrets,
        ))
    return paths


# ── Regra C: má configuração de IaC + segredo no mesmo ativo ────────────────

def _rule_c_iac_plus_secret(vulns: list[Vulnerability],
                             assets: dict[str, Asset]) -> list[AttackPath]:
    """Container/infra mal configurado (root, privileged) somado a segredo
    exposto: o segredo dá o acesso inicial, a má configuração amplia até o host."""
    paths = []
    areas = _areas(vulns)
    by_asset: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        key = v.asset_id or f"__module__{areas.get(v.id, _ROOT_AREA)}"
        by_asset[key].append(v)

    for key, group in by_asset.items():
        iac = [v for v in group if v.scan_type == ScanType.IAC]
        secrets = [v for v in group if v.scan_type == ScanType.SECRETS]
        if not (iac and secrets):
            continue

        asset = assets.get(key) if not key.startswith("__module__") else None
        area = key.replace("__module__", "")
        if asset:
            onde = f"No ativo \"{asset.label}\""
        elif area == _ROOT_AREA:
            onde = "Na raiz do projeto"
        else:
            onde = f"Na pasta {area}"
        paths.append(AttackPath(
            rule_id="C",
            severity="high",
            exposure=f"{len(secrets)} segredo(s) exposto(s)",
            vulnerability=f"{len(iac)} má(s) configuração(ões) de infraestrutura",
            impact="Escalação de privilégio no container/host",
            explanation=(
                f"{onde} há segredo exposto e infraestrutura mal configurada ao mesmo tempo. "
                f"O segredo dá o acesso inicial; a má configuração (execução como root, container "
                f"privilegiado ou rede do host) transforma esse acesso em controle mais amplo do "
                f"ambiente, em vez de ficar contido na aplicação."
            ),
            asset_name=asset.label if asset else None,
            vulns=iac + secrets,
        ))
    return paths


# ── Regra D: ativo crítico com dados sensíveis + achado grave ───────────────

def _rule_d_critical_asset_sensitive(vulns: list[Vulnerability],
                                      assets: dict[str, Asset]) -> list[AttackPath]:
    """Qualquer achado crítico/alto num ativo que é crítico E guarda dados
    sensíveis: caminho curto até o que mais importa."""
    paths = []
    by_asset: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        if v.asset_id:
            by_asset[v.asset_id].append(v)

    for asset_id, asset_vulns in by_asset.items():
        asset = assets.get(asset_id)
        if not asset or not (asset.critical_asset and asset.contains_sensitive_data):
            continue
        graves = [v for v in asset_vulns if v.severity in (Severity.CRITICAL, Severity.HIGH)]
        if not graves:
            continue

        # Evita duplicar a leitura da regra B, que já cobre secrets em ativo exposto
        if asset.internet_facing and all(v.scan_type == ScanType.SECRETS for v in graves):
            continue

        paths.append(AttackPath(
            rule_id="D",
            severity="critical" if any(v.severity == Severity.CRITICAL for v in graves) else "high",
            exposure=f"Ativo crítico com dados sensíveis ({asset.label})",
            vulnerability=f"{len(graves)} vulnerabilidade(s) de severidade alta ou crítica",
            impact="Comprometimento de dados sensíveis em sistema crítico",
            explanation=(
                f"\"{asset.label}\" foi marcado como ativo crítico e guarda dados sensíveis, e "
                f"concentra {len(graves)} achado(s) de severidade alta ou crítica. Mesmo sem uma "
                f"cadeia técnica específica, a combinação de criticidade declarada e achados graves "
                f"coloca esse ativo no topo da fila de correção."
            ),
            asset_name=asset.label,
            vulns=graves,
        ))
    return paths
