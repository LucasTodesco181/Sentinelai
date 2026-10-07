"""
core/threat_intel.py
Inteligência de ameaças para priorização: CISA KEV + FIRST EPSS.

Por que isso existe
-------------------
CVSS mede a gravidade TEÓRICA de uma falha ("se alguém explorar, o estrago
é grande"). Não diz se alguém está de fato explorando. Dois sinais públicos
respondem a essa pergunta, e são os que ASPMs de mercado usam hoje para
sair do "CVSS puro":

  - CISA KEV (Known Exploited Vulnerabilities): catálogo mantido pela
    agência de cibersegurança dos EUA com CVEs que TÊM exploração ativa
    confirmada em ataques reais. Sinal binário e forte.
  - EPSS (Exploit Prediction Scoring System, FIRST.org): probabilidade
    (0–1) de um CVE ser explorado nos próximos 30 dias, recalculada
    diariamente a partir de dados de exploração observados. Sinal contínuo.

Escopo — importante para não superestimar
-----------------------------------------
Os dois só existem para CVEs. Achados de SAST (Semgrep), Secrets
(Gitleaks) e DAST (ZAP) são baseados em regra, não em CVE público, então
não são enriquecidos — continuam priorizados só pelo score heurístico.
Na prática o enriquecimento vale para SCA (Snyk) e Container (Trivy).
Atenção também: o parser do ZAP grava o CWE no campo cve_id (ex.: "79") e
o Trivy às vezes traz IDs GHSA-...; normalize_cve() descarta tudo que não
é CVE-AAAA-NNNN, para não mandar lixo às APIs.

Rede, cache e privacidade
-------------------------
  - O catálogo KEV é baixado inteiro (JSON público, ~1–2 MB).
  - O EPSS é consultado só para os CVEs presentes nos findings, em lotes.
    Nada além de IDs de CVE sai da máquina — nenhum código, caminho de
    arquivo, nome de ativo ou dado da empresa.
  - Tudo fica em cache em data/threat_intel.json e só é rebuscado depois de
    MAX_AGE (24h — o EPSS é recalculado diariamente, o KEV é atualizado em
    dias úteis). Sem internet, o app usa o último cache e segue funcionando;
    sem cache nenhum, a priorização só não ganha esses dois sinais.
  - O conteúdo baixado é tratado como entrada NÃO confiável: só entram IDs
    no formato CVE, probabilidades são limitadas a 0–1 e campos fora do
    formato esperado são ignorados em vez de derrubar a carga.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable

if getattr(sys, "frozen", False):
    _DATA_DIR = Path(os.getenv("APPDATA", str(Path.home()))) / "SentinelAI"
else:
    _DATA_DIR = Path(__file__).parent.parent / "data"

CACHE_FILE = _DATA_DIR / "threat_intel.json"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100              # limite padrão de itens por página da API do EPSS
HTTP_TIMEOUT = 15             # segundos, por requisição
MAX_AGE = timedelta(hours=24)
# Alguns servidores recusam o User-Agent padrão do urllib ("Python-urllib/x").
USER_AGENT = "SentinelAI-ASPM/1.0 (projeto academico; +threat-intel KEV/EPSS)"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_lock = threading.Lock()
_cache: dict | None = None     # carregado sob demanda; ver _get_cache()


# ── Modelo ────────────────────────────────────────────────────────────────────

@dataclass
class ThreatIntel:
    """O que se sabe sobre um CVE. Campos vazios/None = sem informação
    (não confundir com "não é explorado": ver in_kev / epss)."""
    cve: str
    in_kev: bool = False
    kev_date_added: str = ""
    kev_due_date: str = ""
    kev_ransomware: bool = False        # "knownRansomwareCampaignUse" == "Known"
    epss: float | None = None           # 0–1
    epss_percentile: float | None = None  # 0–1
    epss_date: str = ""

    @property
    def has_signal(self) -> bool:
        return self.in_kev or self.epss is not None


@dataclass
class RefreshResult:
    kev_updated: bool = False           # baixou o catálogo agora
    kev_count: int = 0                  # CVEs no catálogo (cache atual)
    epss_fetched: int = 0               # CVEs consultados agora no EPSS
    errors: list[str] = field(default_factory=list)
    attempted: bool = False             # houve alguma tentativa de rede

    @property
    def ok(self) -> bool:
        return not self.errors


# ── Utilidades ───────────────────────────────────────────────────────────────

def normalize_cve(value) -> str | None:
    """'cve-2021-44228 ' -> 'CVE-2021-44228'; qualquer coisa que não seja um
    ID CVE (CWE do ZAP, GHSA do Trivy, None) -> None."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip().upper()
    return v if _CVE_RE.match(v) else None


def _to_prob(value) -> float | None:
    """A API do EPSS devolve números como texto ('0.944010000'). Aceita str
    ou número; fora de 0–1 ou inválido -> None (entrada não confiável)."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f != f or f < 0 or f > 1:   # NaN ou fora da faixa
        return None
    return f


def _now() -> datetime:
    return datetime.now()


def _is_stale(iso: str | None, now: datetime | None = None) -> bool:
    if not iso:
        return True
    try:
        ts = datetime.fromisoformat(iso)
    except ValueError:
        return True
    return (now or _now()) - ts > MAX_AGE


# Tentativas extras só para falhas de rede TRANSITÓRIAS — a conexão caiu no
# meio do download (comum em wifi de laboratório/proxy que corta conexão
# longa em respostas grandes, como o catálogo KEV de ~1.7-2MB), não que o
# servidor recusou o pedido. Erros permanentes (403, CVE inválido, HTTPS
# exigido) não entram aqui — tentar de novo não muda o resultado.
_TRANSIENT_RETRIES = 2
_TRANSIENT_BACKOFF = 1.5  # segundos, multiplicado a cada tentativa


def _http_get_json(url: str) -> object:
    """GET HTTPS -> JSON. Separado para os testes poderem substituir sem
    rede (parâmetro fetch= de refresh())."""
    if not url.startswith("https://"):
        raise ValueError("apenas HTTPS é permitido")
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept": "application/json",
    })

    attempt = 0
    while True:
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (http.client.IncompleteRead, ConnectionError, TimeoutError,
                http.client.BadStatusLine):
            attempt += 1
            if attempt > _TRANSIENT_RETRIES:
                raise
            time.sleep(_TRANSIENT_BACKOFF * attempt)


# ── Cache ────────────────────────────────────────────────────────────────────

def _empty_cache() -> dict:
    return {"kev": {"updated_at": None, "catalog_version": "", "entries": {}}, "epss": {}}


def _load_cache_file() -> dict:
    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                base = _empty_cache()
                kev = data.get("kev")
                if isinstance(kev, dict) and isinstance(kev.get("entries"), dict):
                    base["kev"].update({
                        "updated_at": kev.get("updated_at"),
                        "catalog_version": kev.get("catalog_version", ""),
                        "entries": kev["entries"],
                    })
                if isinstance(data.get("epss"), dict):
                    base["epss"] = data["epss"]
                return base
    except Exception as e:
        print(f"[threat_intel] Cache ilegível, ignorado: {e}")
    return _empty_cache()


def _get_cache() -> dict:
    global _cache
    if _cache is None:
        _cache = _load_cache_file()
    return _cache


def _save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_FILE.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
        os.replace(tmp, CACHE_FILE)   # troca atômica: nunca deixa o cache pela metade
    except Exception as e:
        print(f"[threat_intel] Erro ao salvar cache: {e}")


def reset_cache_for_tests(path: Path | None = None) -> None:
    """Só para testes: aponta para outro arquivo e zera o estado em memória."""
    global _cache, CACHE_FILE
    with _lock:
        if path is not None:
            CACHE_FILE = path
        _cache = None


# ── Consulta (thread de UI — só lê o cache, nunca vai à rede) ─────────────────

def lookup(cve_id) -> ThreatIntel | None:
    """Inteligência conhecida para o CVE, a partir do cache. None quando o
    valor não é um CVE (SAST/Secrets/DAST, CWE do ZAP, GHSA...)."""
    cve = normalize_cve(cve_id)
    if cve is None:
        return None
    with _lock:
        cache = _get_cache()
        kev = cache["kev"]["entries"].get(cve)
        ep = cache["epss"].get(cve)
    info = ThreatIntel(cve=cve)
    if isinstance(kev, dict):
        info.in_kev = True
        info.kev_date_added = str(kev.get("date_added", ""))
        info.kev_due_date = str(kev.get("due_date", ""))
        info.kev_ransomware = bool(kev.get("ransomware", False))
    if isinstance(ep, dict):
        info.epss = _to_prob(ep.get("epss"))
        info.epss_percentile = _to_prob(ep.get("percentile"))
        info.epss_date = str(ep.get("score_date", "") or "")
    return info


def status() -> dict:
    """Resumo do cache para a tela de Configurações."""
    with _lock:
        cache = _get_cache()
        return {
            "kev_updated_at": cache["kev"]["updated_at"],
            "kev_count": len(cache["kev"]["entries"]),
            "kev_catalog_version": cache["kev"]["catalog_version"],
            "epss_count": sum(1 for e in cache["epss"].values()
                              if isinstance(e, dict) and e.get("epss") is not None),
        }


def needs_refresh(cves: Iterable[str], now: datetime | None = None) -> bool:
    """Há algo a buscar? KEV velho/ausente, ou algum CVE sem EPSS recente.
    Sem nenhum CVE nos findings não há motivo para ir à rede."""
    wanted = {c for c in (normalize_cve(x) for x in cves) if c}
    if not wanted:
        return False
    with _lock:
        cache = _get_cache()
        if _is_stale(cache["kev"]["updated_at"], now):
            return True
        for cve in wanted:
            ep = cache["epss"].get(cve)
            if not isinstance(ep, dict) or _is_stale(ep.get("fetched_at"), now):
                return True
    return False


# ── Atualização (roda em thread de fundo — pode demorar / falhar) ─────────────

def _parse_kev(payload) -> tuple[dict, str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("formato inesperado do catálogo KEV")
    entries = {}
    for item in payload["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve = normalize_cve(item.get("cveID"))
        if not cve:
            continue
        entries[cve] = {
            "date_added": str(item.get("dateAdded", ""))[:10],
            "due_date": str(item.get("dueDate", ""))[:10],
            "ransomware": str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
        }
    if not entries:
        raise ValueError("catálogo KEV vazio ou ilegível")
    return entries, str(payload.get("catalogVersion", ""))[:32]


def _parse_epss(payload) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("formato inesperado da resposta do EPSS")
    out = {}
    for item in payload["data"]:
        if not isinstance(item, dict):
            continue
        cve = normalize_cve(item.get("cve"))
        epss = _to_prob(item.get("epss"))
        if not cve or epss is None:
            continue
        out[cve] = {
            "epss": epss,
            "percentile": _to_prob(item.get("percentile")),
            "score_date": str(item.get("date", ""))[:10],
        }
    return out


def refresh(cves: Iterable[str], force: bool = False,
            fetch: Callable[[str], object] = _http_get_json) -> RefreshResult:
    """Atualiza o cache. Cada fonte falha de forma independente: se o KEV
    cair e o EPSS responder (ou vice-versa), o que deu certo é salvo e o
    resto continua com o cache anterior. Nunca levanta exceção."""
    result = RefreshResult()
    wanted = sorted({c for c in (normalize_cve(x) for x in cves) if c})
    now = _now()
    now_iso = now.isoformat(timespec="seconds")

    with _lock:
        cache = _get_cache()
        kev_stale = force or _is_stale(cache["kev"]["updated_at"], now)
        epss_todo = [c for c in wanted
                     if force or not isinstance(cache["epss"].get(c), dict)
                     or _is_stale(cache["epss"][c].get("fetched_at"), now)]

    if not wanted and not force:
        result.kev_count = status()["kev_count"]
        return result

    new_kev = None
    if kev_stale:
        result.attempted = True
        try:
            new_kev = _parse_kev(fetch(KEV_URL))
            result.kev_updated = True
        except Exception as e:
            result.errors.append(f"CISA KEV: {e}")

    new_epss: dict[str, dict] = {}
    for i in range(0, len(epss_todo), EPSS_BATCH):
        batch = epss_todo[i:i + EPSS_BATCH]
        result.attempted = True
        url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(batch), 'limit': EPSS_BATCH})}"
        try:
            found = _parse_epss(fetch(url))
        except Exception as e:
            result.errors.append(f"EPSS: {e}")
            break   # sem rede, os próximos lotes também vão falhar
        for cve in batch:
            # CVE que o EPSS não conhece (muito novo, rejeitado) também é
            # registrado, com epss=None — senão seria rebuscado a cada abertura.
            entry = found.get(cve, {"epss": None, "percentile": None, "score_date": ""})
            entry["fetched_at"] = now_iso
            new_epss[cve] = entry
        result.epss_fetched += len(batch)

    with _lock:
        cache = _get_cache()
        if new_kev is not None:
            entries, version = new_kev
            cache["kev"] = {"updated_at": now_iso, "catalog_version": version, "entries": entries}
        cache["epss"].update(new_epss)
        if new_kev is not None or new_epss:
            _save_cache(cache)
        result.kev_count = len(cache["kev"]["entries"])
    return result
