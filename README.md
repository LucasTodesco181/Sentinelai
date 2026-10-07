# SentinelAI — ASPM (Application Security Posture Management)
> Protótipo técnico | Python + PyQt6

## Visão Geral
Dashboard desktop que agrega relatórios de múltiplas ferramentas de segurança,
normaliza tudo em um modelo único de vulnerabilidade e calcula um score de
postura de segurança — com uma camada de IA que explica, prioriza e detecta
padrões, sempre considerando o contexto real da empresa e dos ativos
cadastrados.

## Ferramentas Integradas
| Ferramenta | Tipo(s)                              | Formato de entrada | Execução interna |
|------------|---------------------------------------|---------------------|---------------------|
| Trivy      | SCA + Container + IaC + Secrets        | JSON                | Sim (`scanners/trivy_scanner.py`) |
| Grype      | SCA (2º motor, ao lado do Trivy)       | JSON                | Sim (`scanners/grype_scanner.py`) |
| Semgrep    | SAST                                   | JSON                | Sim (`scanners/semgrep_scanner.py`) |
| Gitleaks   | Secrets                                | JSON                | Sim (`scanners/gitleaks_scanner.py`) |
| OWASP ZAP  | DAST                                   | JSON / XML          | Sim, contra uma URL (`scanners/zap_scanner.py`, via Docker) |
| Snyk       | SCA                                    | JSON                | Não (importação manual — exige conta/token) |

O Trivy cobre vários estágios num único relatório e classifica os achados de
pacote conforme o que foi escaneado: numa **pasta** de projeto (`package.json`,
`pom.xml`, `requirements.txt`...) os CVEs são **SCA**; numa **imagem Docker**
são **Container**. Também traz más configurações de Dockerfile/Kubernetes/
Terraform (IaC) e segredos expostos (Secrets). O **Grype** roda junto como um
segundo motor de SCA: as bases de vulnerabilidade dos dois são parcialmente
diferentes, então um CVE que um não catalogou o outro pode pegar — e onde os
dois concordam, o sinal é mais forte.

Trivy, Grype, Semgrep e Gitleaks são disparados direto pelo app contra uma
pasta de projeto ("Escanear Pasta", requer os binários no PATH). O ZAP tem
fluxo próprio, **"Escanear URL (ZAP)"**: o alvo é uma aplicação já rodando
(ex.: `http://localhost:3000`), executada pela imagem Docker
`zaproxy/zap-stable` (baseline scan, passivo). O Snyk continua só via
importação manual do relatório, por depender de conta autenticada.

## Navegação (sidebar)
- **Dashboard** — score de postura, distribuição de achados por ferramenta e
  por tipo de scan. Sem nenhum relatório importado ainda, mostra um checklist
  de primeiros passos em vez de um painel zerado — a ASPM nunca afirma
  cobertura que não tem.
- **Findings** — lista completa das vulnerabilidades normalizadas, com busca,
  ordenação por coluna, filtros (severidade, ferramenta, status, ativo) e
  vínculo de findings a ativos cadastrados.
- **Inteligência Artificial**, dividida em seis sub-abas:
  - *Explicar Vuln* — explica uma vulnerabilidade em linguagem simples, sem jargão.
  - *Resumo Executivo* — visão geral dos findings abertos para quem decide.
  - *Priorização IA* — ranking de prioridade combinando heurística determinística
    e reordenação por LLM (ver seção abaixo).
  - *Exploração Ativa (KEV)* — findings cujo CVE está no catálogo CISA KEV
    (exploração real confirmada), ordenados pelo prazo de correção da CISA.
    Dado determinístico, não depende de IA.
  - *Probabilidade (EPSS)* — findings com CVE ordenados pela probabilidade de
    exploração nos próximos 30 dias (FIRST EPSS).
  - *Padrões & Anomalias* — padrões recorrentes, módulos mais afetados
    (hotspots) e correlações suspeitas entre relatórios importados.
- **Attack Path** — cruza os findings importados com o contexto dos ativos
  para montar cadeias de risco (exposição → vulnerabilidade → impacto).
  Determinístico, não depende de IA.
- **Ativos** — CRUD de aplicações/serviços da empresa (ambiente, exposição à
  internet, criticidade, dados sensíveis) — dá contexto por sistema à
  priorização e ao Attack Path.
- **Contexto da Empresa** — formulário com setor, porte, prioridades de
  negócio (disponibilidade/confidencialidade/integridade), dados sensíveis,
  exposição à internet, infraestrutura e regulamentações. Usado tanto no
  score determinístico quanto injetado no prompt da IA.

## Priorização Inteligente (score transparente)
O score de cada vulnerabilidade é a soma de parcelas nomeadas — não uma caixa
preta:

```
Severidade base (crítica): +40
CVSS (9.8):                +24.5
Segredo exposto:           +15
Confidencialidade prioritária (contexto): +8
Setor Financeiro (contexto):              +5
──────────────────────────────────────────
Pre-score:                                92.5  (teto: 100)
```

Esse pre-score determinístico é combinado (70/30) com a reordenação do LLM
(quando a IA responde), que também justifica sua posição no ranking; cada card
mostra a conta do score final. Fora do top 10 avaliado pela IA a parcela da IA
é 0, então nenhum item de fora passa à frente de um do top. Sem contexto de empresa
preenchido ou sem IA disponível, o app cai automaticamente em critérios
técnicos padrão — nunca trava a funcionalidade.

### Exploração real: CISA KEV + EPSS
CVSS mede a gravidade *teórica*; não diz se alguém está explorando. Para
findings com CVE, o score ganha dois sinais públicos de exploração real:

```
CISA KEV — exploração ativa confirmada:  +30
KEV: usada em campanhas de ransomware:   +5
EPSS 94.4%, percentil 100:               +23.6   (EPSS × 25)
```

- **CISA KEV** — catálogo de CVEs com exploração ativa confirmada em ataques
  reais. Um CVE médio que está sendo explorado hoje passa na frente de um
  crítico que ninguém explora.
- **EPSS (FIRST.org)** — probabilidade de exploração nos próximos 30 dias.
- Aparecem também no painel de detalhe do Findings (pílula "CISA KEV" +
  linha EPSS), nos cards da Priorização e no contexto enviado à IA.
- **Só vale para CVEs** (na prática SCA — Trivy, Grype, Snyk — e Container). SAST, Secrets
  e DAST são achados por regra, sem CVE público, e seguem só na heurística.
- Atualiza sozinho em segundo plano (cache de 24h em `data/threat_intel.json`)
  e manualmente em Configurações → *Atualizar agora*. Sem internet, usa o
  último cache e o app segue funcionando. Só IDs de CVE saem da máquina.

## Inteligência Artificial
A aba de IA usa um provider com fallback automático:
1. **Ollama local** (`http://localhost:11434`, modelo `gemma3:4b`) — privado, sem internet.
2. **Groq API** (`https://api.groq.com`) — gratuito, precisa de chave. Também é usada
   se o Ollama estiver rodando mas sem o modelo instalado.

Temperatura fixa em **0.2** nos dois backends (`LLMProvider.TEMPERATURE`): respostas
consistentes e reproduzíveis, importante para explicar e priorizar risco.

A Groq API Key é configurada em **Configurações** (botão na barra da aba de
IA) e persiste em `data/settings.json` — arquivo local, fora do controle de
versão (ver `.gitignore`).

## Estrutura do Projeto
```
sentinelai_merged/
├── main.py                      # Entrypoint PyQt6
├── requirements.txt
├── core/
│   ├── models.py                 # Dataclasses: Vulnerability, ScanReport, PostureScore...
│   ├── aggregator.py             # Detecta o parser certo e agrega os relatórios
│   ├── scorer.py                 # Calcula o score de postura (0-100)
│   ├── coverage.py               # Quais tipos de scan foram efetivamente executados
│   ├── company_context.py        # Modelo + persistência do Contexto da Empresa
│   ├── asset.py                  # Modelo + persistência dos Ativos
│   ├── attack_path.py            # Motor determinístico de cadeias de risco
│   ├── finding_store.py          # Persistência dos findings + merge por fingerprint
│   ├── finding_identity.py       # Fingerprint determinístico de um finding
│   ├── scan_history.py           # Histórico leve de execuções de scan
│   ├── threat_intel.py           # CISA KEV + EPSS (fetch, cache, consulta)
│   ├── gitleaks_i18n.py          # Descrições do Gitleaks em português (por RuleID)
│   └── settings.py               # Configurações do app (Groq API Key)
├── parsers/
│   ├── base_parser.py            # Interface abstrata
│   ├── semgrep_parser.py         # Semgrep JSON → Vulnerability
│   ├── zap_parser.py             # ZAP JSON/XML → Vulnerability
│   ├── snyk_parser.py            # Snyk JSON → Vulnerability
│   ├── gitleaks_parser.py        # Gitleaks JSON → Vulnerability
│   ├── grype_parser.py           # Grype JSON → Vulnerability (SCA)
│   └── trivy_parser.py           # Trivy JSON → Vulnerability (SCA/Container/IaC/Secrets)
├── scanners/
│   ├── base_scanner.py           # Interface abstrata
│   ├── trivy_scanner.py          # Executa o Trivy internamente
│   ├── semgrep_scanner.py        # Executa o Semgrep internamente
│   ├── gitleaks_scanner.py       # Executa o Gitleaks internamente
│   ├── grype_scanner.py          # Executa o Grype internamente
│   └── zap_scanner.py            # Executa o ZAP (baseline) contra uma URL, via Docker
├── ai/
│   ├── provider.py                # Abstração de LLM (Ollama local ou Groq)
│   ├── explainer.py               # Explica vulnerabilidades / resumo executivo
│   ├── prioritizer.py             # Priorização (heurística com breakdown + LLM)
│   └── anomaly_detector.py        # Padrões, hotspots e correlações
├── ui/
│   ├── main_window.py             # QMainWindow principal (sidebar + views)
│   ├── theme.py                   # Paleta de cores central da UI
│   ├── icons.py                   # Ícones vetoriais via QPainter
│   ├── charts.py                  # Gráficos via QPainter (sem libs externas)
│   ├── formatting.py              # Formatação comum de findings (local, severidade, texto)
│   ├── easter_eggs.py             # easter eggs escondidos
│   ├── dialogs/
│   │   └── settings_dialog.py     # Diálogo de Configurações (Groq API Key)
│   ├── widgets/
│   │   ├── ai_results.py          # Cards estruturados de Priorização, Anomalias e Attack Path
│   │   ├── data_actions.py        # Escanear/Importar/Limpar + progresso do scan
│   │   ├── finding_detail.py      # Painel de detalhe de um finding (descrição, correção, triagem)
│   │   └── view_header.py         # Cabeçalho padrão compartilhado entre views
│   └── views/
│       ├── dashboard_view.py
│       ├── findings_view.py
│       ├── ai_view.py
│       ├── attack_path_view.py
│       ├── assets_view.py
│       └── context_view.py        # Formulário do Contexto da Empresa
├── packaging/                    # Geração de instalador Windows (.exe)
│   ├── build_exe.bat
│   ├── installer.iss
│   └── INSTALACAO.md
├── assets/                       # Ícone do app (.ico / .png)
├── data/
│   └── samples/                  # JSONs de exemplo para cada ferramenta
└── utils/
```

## Requisitos
- **Python 3.10+** (o código usa a sintaxe de tipos `X | None`)
- **Obrigatório**: as dependências de `requirements.txt` (inclui o PyQt6)
- **Opcional** — só necessário se for usar *"Escanear Pasta"* (scanners
  internos), cada um requer o binário correspondente instalado e disponível
  no `PATH`:
  - [Trivy](https://trivy.dev) (`trivy`)
  - [Semgrep](https://semgrep.dev) (`pip install semgrep` já coloca no PATH)
  - [Gitleaks](https://github.com/gitleaks/gitleaks) (`gitleaks`)
  - [Grype](https://github.com/anchore/grype) (`grype`)
- **Opcional** — só necessário para *"Escanear URL (ZAP)"*:
  [Docker](https://www.docker.com) com a imagem `zaproxy/zap-stable`
  (`docker pull zaproxy/zap-stable`) e uma aplicação já rodando para escanear.
- **Opcional** — só necessário para a aba **Inteligência Artificial**:
  [Ollama](https://ollama.com) rodando local, **ou** uma
  [Groq API key](https://console.groq.com/keys) (gratuita).

- **Opcional** — internet, para baixar CISA KEV e EPSS (sem ela, a
  priorização só não ganha esses dois sinais).

Sem nenhum dos itens opcionais instalados/configurados, o app roda normal —
"Escanear Pasta" fica indisponível (use "Importar Relatório" no lugar) e a
priorização cai automaticamente no cálculo determinístico, sem IA.

### Instalação no Windows (PowerShell)
Os binários dos scanners não têm instalador único — a forma mais simples no
Windows é via [Scoop](https://scoop.sh) (não precisa de administrador):

```powershell
# 0. Scoop, se ainda não tiver
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

# 1. Dependências Python
pip install -r requirements.txt

# 2. Scanners
scoop bucket add main
scoop install trivy gitleaks grype
pip install semgrep

# 3. Aquecer bases de dados (evita demora/timeout na primeira execução)
trivy fs --download-db-only .
grype db update

# 4. IA local (opcional) — instale o Ollama em
#    https://ollama.com/download/windows, depois:
ollama pull gemma3:4b
```

Docker Desktop (para o ZAP) não tem instalação via linha de comando — baixe
em https://www.docker.com/products/docker-desktop, abra, e então:

```powershell
docker pull zaproxy/zap-stable
```

## Como Executar
```powershell
pip install -r requirements.txt
python main.py
```
Para habilitar a IA, configure a Groq API key em **Configurações** (dentro
da aba Inteligência Artificial) — ou apenas deixe o Ollama rodando local
(`ollama pull gemma3:4b`), que é detectado automaticamente.

## Como Usar
**Primeira execução:** com nenhum dado importado ainda, o Dashboard mostra um
checklist de primeiros passos em vez de um painel zerado — siga a ordem
abaixo:

1. **(Opcional, recomendado) Preencha o Contexto da Empresa** — setor, porte,
   prioridades de negócio (disponibilidade/confidencialidade/integridade),
   dados sensíveis e infraestrutura. Melhora o score e entra no prompt da IA.
2. **(Opcional) Cadastre os Ativos** — aplicações/serviços da empresa, com
   ambiente, exposição à internet e criticidade. Habilita a aba **Attack
   Path** e refina a priorização por sistema.
3. **Traga os findings** pelos botões no cabeçalho do Dashboard ou de
   Findings, de duas formas (pode combinar as duas):
   - **"Escanear Pasta"** — roda Trivy/Semgrep/Gitleaks/Grype direto contra um
     projeto local (precisa dos binários no PATH, ver Requisitos acima). O
     progresso ("Etapa 2 de 4 — Semgrep") aparece no próprio cabeçalho, com
     opção de cancelar.
   - **"Escanear URL (ZAP)"** — roda o OWASP ZAP contra uma aplicação já
     rodando (ex.: `http://localhost:3000`). Pode levar alguns minutos.
   - **"Importar Relatório"** — carrega um relatório já gerado por qualquer
     uma das 6 ferramentas suportadas (Semgrep, ZAP, Snyk, Gitleaks,
     Trivy ou Grype), ou use os exemplos prontos em `data/samples/` pra testar sem
     precisar rodar nenhuma ferramenta de verdade. O formato é detectado
     automaticamente.
4. **Veja o Dashboard** — o score de postura é recalculado em tempo real, com
   a distribuição de achados por ferramenta e por tipo de scan, e anéis de
   risco em 3 estados (sem cobertura / coberto e limpo / coberto com risco).
5. **Explore os Findings** — busque por título, CVE ou arquivo, ordene
   clicando nas colunas e filtre por severidade/ferramenta/status/ativo.
   Clique numa linha para abrir o **painel de detalhe**: descrição, como
   corrigir (quando a ferramenta traz), arquivo:linha completo, CVE/CVSS, e a
   triagem — mudar o status e vincular a um ativo. Para mudar vários de uma
   vez, selecione as linhas e use o clique direito.
6. **Use a Inteligência Artificial** (configure a chave em Configurações,
   dentro da própria aba): explique uma vulnerabilidade específica em
   linguagem simples (ou direto do painel de detalhe, em "Explicar com IA"),
   gere um resumo executivo, rode a priorização com o breakdown do score, ou
   detecte padrões e anomalias. Resumo, priorização e padrões consideram só
   os findings com status **Aberta**.
7. **Consulte o Attack Path** — cruza os findings com o contexto dos ativos
   pra montar cadeias de risco (exposição → vulnerabilidade → impacto).
   Determinístico, não depende de IA nem de nenhuma etapa anterior além do
   cadastro de ativos.

## Gerar Instalador Windows (.exe)
Veja `packaging/INSTALACAO.md` — transforma o projeto em um
`SentinelAI_Setup.exe` que instala sem precisar de Python nem pip na máquina
do usuário final.
