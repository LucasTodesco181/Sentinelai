# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
core/gitleaks_i18n.py
Traduz a descrição das regras padrão do Gitleaks para português.

O Gitleaks não tem opção de saída em pt-br — o campo `Description` do
relatório vem embutido na regra (texto fixo em inglês, definido pela
própria ferramenta), diferente de `Commit`/`Author`/`Secret`, que já eram
rotulados em português pelo parser. Isso é o mesmo caso do CVE do
Trivy/Snyk (texto vindo direto da NVD) — a diferença é que o Gitleaks usa
um conjunto FIXO e pequeno de regras padrão (github.com/gitleaks/gitleaks,
config/gitleaks.toml), então dá pra traduzir por RuleID sem precisar
chamar IA a cada finding (mais rápido, sem custo, determinístico).

Duas camadas:
  1) Tradução exata por RuleID — cobre as regras mais comuns/prováveis de
     aparecer num scan real (chaves de nuvem, tokens de SaaS conhecidos).
  2) Fallback por palavra-chave no próprio RuleID — cobre qualquer regra
     não mapeada (inclusive regras customizadas de quem usa o Gitleaks com
     config própria) com uma frase genérica mas útil.

Em ambos os casos, o texto original da ferramenta é preservado (quem
chama esta função decide onde/como exibi-lo) — a tradução é um resumo,
não substitui o dado original pra fins de auditoria.
"""

# Camada 1 — regras padrão mais comuns. Não é a lista completa (~150) do
# Gitleaks; cobre os provedores/serviços mais frequentes em relatórios
# reais. RuleID desconhecido cai no fallback por palavra-chave abaixo.
_EXACT: dict[str, str] = {
    "generic-api-key":
        "Chave de API genérica detectada, com potencial acesso a diversos serviços e operações sensíveis.",
    "aws-access-token":
        "Credencial de acesso da AWS (Access Key) exposta — pode permitir acesso amplo aos recursos da conta na nuvem.",
    "private-key":
        "Chave privada (criptográfica) exposta — pode ser usada para se passar pelo dono da chave ou descriptografar dados protegidos.",
    "jwt":
        "Token JWT exposto no código — dependendo do payload, pode permitir personificação de usuário ou escalonamento de privilégio.",
    "github-pat":
        "Personal Access Token do GitHub exposto — pode dar acesso a repositórios privados, Actions e integrações da conta.",
    "github-fine-grained-pat":
        "Fine-grained Personal Access Token do GitHub exposto — acesso a repositórios e permissões conforme o escopo configurado no token.",
    "gitlab-pat":
        "Personal Access Token do GitLab exposto — mesmo risco do GitHub, mas para projetos hospedados no GitLab.",
    "slack-access-token":
        "Token de acesso do Slack exposto — pode permitir ler mensagens, postar como o bot/usuário ou acessar arquivos do workspace.",
    "slack-web-hook":
        "Webhook do Slack exposto — pode permitir postar mensagens no workspace em nome da integração.",
    "stripe-access-token":
        "Chave de API do Stripe exposta — risco direto de fraude financeira (pagamentos, reembolsos, dados de cliente).",
    "square-access-token":
        "Token de acesso do Square exposto — risco financeiro direto (pagamentos e dados de transação).",
    "twilio-api-key":
        "Chave de API da Twilio exposta — pode permitir enviar SMS/chamadas em nome da conta, gerando custo e abuso.",
    "sendgrid-api-token":
        "Token da SendGrid exposto — pode permitir enviar e-mails em nome do domínio (phishing/spam).",
    "mailchimp-api-key":
        "Chave de API do Mailchimp exposta — pode expor listas de contatos e permitir envio de campanhas não autorizadas.",
    "mailgun-private-api-token":
        "Token privado da Mailgun exposto — pode permitir enviar e-mails em nome do domínio configurado.",
    "npm-access-token":
        "Token de acesso do npm exposto — pode permitir publicar pacotes maliciosos em nome da conta/organização.",
    "pypi-upload-token":
        "Token de upload do PyPI exposto — mesmo risco do npm, mas para pacotes Python.",
    "dockerhub-pat":
        "Personal Access Token do Docker Hub exposto — pode permitir publicar ou alterar imagens da conta/organização.",
    "google-api-key":
        "Chave de API do Google exposta — pode gerar cobranças indevidas ou dar acesso a serviços do Google Cloud vinculados.",
    "gcp-api-key":
        "Chave de API do Google Cloud Platform exposta — pode gerar cobranças indevidas ou acesso a serviços vinculados ao projeto.",
    "heroku-api-key":
        "Chave de API da Heroku exposta — pode permitir gerenciar ou destruir aplicações hospedadas na conta.",
    "dropbox-api-token":
        "Token de API do Dropbox exposto — pode permitir ler, alterar ou apagar arquivos armazenados na conta.",
    "digitalocean-pat":
        "Personal Access Token da DigitalOcean exposto — pode permitir gerenciar ou destruir recursos na conta (droplets, bancos, etc.).",
    "discord-api-token":
        "Token de bot do Discord exposto — pode permitir controlar o bot em todos os servidores onde está presente.",
    "telegram-bot-token":
        "Token de bot do Telegram exposto — pode permitir controlar o bot e ler/enviar mensagens em nome dele.",
    "okta-access-token":
        "Token de acesso do Okta exposto — risco alto: o Okta costuma centralizar a autenticação de toda a organização.",
}

# Camada 2 — fallback por palavra-chave, pra qualquer RuleID não mapeado
# acima (inclusive regras customizadas). Ordem importa: a primeira
# palavra-chave que bater no RuleID (minúsculo) decide a categoria.
_KEYWORDS: list[tuple[str, str]] = [
    ("private-key", "Chave privada (criptográfica) exposta"),
    ("privatekey", "Chave privada (criptográfica) exposta"),
    ("password", "Senha exposta em texto plano"),
    ("passwd", "Senha exposta em texto plano"),
    ("jwt", "Token JWT exposto"),
    ("webhook", "URL de webhook exposta"),
    ("aws", "Credencial da AWS exposta"),
    ("gcp", "Credencial do Google Cloud exposta"),
    ("google", "Credencial/chave do Google exposta"),
    ("azure", "Credencial do Azure exposta"),
    ("api-key", "Chave de API exposta"),
    ("apikey", "Chave de API exposta"),
    ("access-token", "Token de acesso exposto"),
    ("accesstoken", "Token de acesso exposto"),
    ("pat", "Personal Access Token exposto"),
    ("token", "Token de autenticação exposto"),
    ("secret", "Segredo/credencial exposto"),
]

_GENERIC_FALLBACK = "Segredo/credencial exposto"


def translate_description(rule_id: str) -> str:
    """
    Retorna uma descrição em português para a regra do Gitleaks. Sempre
    devolve algo utilizável — na pior das hipóteses, uma frase genérica
    citando o RuleID original (nunca deixa o campo vazio).
    """
    key = (rule_id or "").strip().lower()
    if key in _EXACT:
        return _EXACT[key]

    for keyword, phrase in _KEYWORDS:
        if keyword in key:
            return f"{phrase} — serviço/tipo não catalogado especificamente (regra: {rule_id})."

    return f"{_GENERIC_FALLBACK} pela regra '{rule_id}' do Gitleaks."
