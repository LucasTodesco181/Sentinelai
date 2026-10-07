# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
ai/provider.py
Abstração de provider LLM com fallback automático.

Prioridade:
  1. Ollama local (http://localhost:11434) — privado, sem internet
  2. Groq API   (https://api.groq.com)    — gratuito, rápido, precisa de chave

Uso:
    provider = LLMProvider()
    response = provider.chat("Explique esta vulnerabilidade...")
"""
import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass
from enum import Enum


class Backend(str, Enum):
    OLLAMA = "ollama"
    GROQ   = "groq"
    NONE   = "none"


@dataclass
class LLMResponse:
    text: str
    backend: Backend
    model: str


class LLMProvider:
    # Temperatura única pros dois backends. Baixa de propósito: isso aqui
    # explica vulnerabilidade e prioriza risco, não é chat criativo — quanto
    # mais alta a temperatura, mais a mesma vulnerabilidade pode sair
    # explicada de um jeito diferente a cada scan, o que é ruim tanto pra
    # confiar no resultado quanto pra reproduzir um bug relatado por alguém.
    # 0.2 fica no meio da faixa 0.1–0.3 que o time decidiu usar.
    # Antes disso: só o Groq mandava temperature (fixo em 0.3, no teto da
    # faixa) — o Ollama, que é o backend PRIORITÁRIO (local, tentado
    # primeiro), não mandava nada e rodava no default do próprio Ollama
    # (bem mais alto, ~0.8) sem ninguém perceber.
    TEMPERATURE = 0.2

    # Modelos preferidos por backend
    OLLAMA_MODEL  = "gemma3:4b"
    # Lista de modelos em ordem de preferência — tenta o próximo se o atual falhar
    GROQ_MODELS = [
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "groq/compound-mini",
        "qwen/qwen3.6-27b",
    ]
    GROQ_MODEL    = GROQ_MODELS[0]  # modelo ativo atual

    OLLAMA_URL = "http://localhost:11434/api/chat"
    GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self, groq_api_key: str | None = None):
        self._groq_key = groq_api_key or os.getenv("GROQ_API_KEY", "")
        self._backend  = self._detect_backend()

    # ------------------------------------------------------------------
    def _detect_backend(self) -> Backend:
        """Testa Ollama local primeiro; cai para Groq se disponível."""
        if self._test_ollama():
            return Backend.OLLAMA
        if self._groq_key:
            return Backend.GROQ
        return Backend.NONE

    def _test_ollama(self) -> bool:
        try:
            req = urllib.request.Request(
                "http://localhost:11434/api/tags",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    @property
    def available(self) -> bool:
        return self._backend != Backend.NONE

    @property
    def backend_name(self) -> str:
        return self._backend.value

    def set_groq_key(self, key: str):
        self._groq_key = key
        if self._backend == Backend.NONE and key:
            self._backend = Backend.GROQ

    # ------------------------------------------------------------------
    def chat(self, prompt: str, system: str = "", timeout: int = 60) -> LLMResponse:
        """
        Envia uma mensagem para o LLM ativo e retorna a resposta.
        Lança RuntimeError se nenhum backend estiver disponível.
        """
        if self._backend == Backend.OLLAMA:
            try:
                return self._ollama_chat(prompt, system, timeout)
            except Exception as e:   # noqa: BLE001 — qualquer falha do Ollama local
                # O backend é decidido UMA vez, na abertura, só perguntando se
                # o Ollama responde. Ollama rodando sem o modelo baixado (HTTP
                # 404), ou fechado depois do app abrir, fazia toda função de IA
                # falhar mesmo com uma chave Groq salva — sem tentar o Groq.
                if self._groq_key:
                    return self._groq_chat(prompt, system, timeout)
                if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                    raise RuntimeError(
                        f"O Ollama está rodando, mas o modelo {self.OLLAMA_MODEL} não está instalado.\n"
                        f"Rode:  ollama pull {self.OLLAMA_MODEL}\n"
                        "ou configure uma chave Groq nas Configurações."
                    ) from None
                raise
        if self._backend == Backend.GROQ:
            return self._groq_chat(prompt, system, timeout)
        raise RuntimeError(
            "Nenhum backend de IA disponível.\n"
            "• Instale o Ollama: https://ollama.com  →  ollama pull gemma3:4b\n"
            "• Ou configure GROQ_API_KEY (gratuito em https://console.groq.com)"
        )

    # ------------------------------------------------------------------
    def _ollama_chat(self, prompt: str, system: str, timeout: int) -> LLMResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = json.dumps({
            "model": self.OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.TEMPERATURE},
        }).encode()

        req = urllib.request.Request(
            self.OLLAMA_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))

        text = ((data.get("message") or {}).get("content") or "").strip()
        if not text:
            raise RuntimeError("O Ollama devolveu uma resposta vazia.")
        return LLMResponse(text=text, backend=Backend.OLLAMA, model=self.OLLAMA_MODEL)

    def _groq_chat(self, prompt: str, system: str, timeout: int) -> LLMResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        last_error = None
        rate_limited = False
        empty_reply = False
        for model in self.GROQ_MODELS:
            body = json.dumps({
                "model": model,
                "messages": messages,
                "max_tokens": 4096,   # modelos de raciocínio gastam parte disso "pensando"
                "temperature": self.TEMPERATURE,
            }).encode()

            req = urllib.request.Request(
                self.GROQ_URL,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._groq_key}",
                    # Sem um User-Agent "normal", a Groq (atrás de WAF/Cloudflare)
                    # devolve 403 para o User-Agent padrão do urllib
                    # ("Python-urllib/x.y"), mesmo com a chave correta.
                    "User-Agent": "aspm-app/1.0 (+https://github.com)",
                    "Accept": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    raw = r.read()
                    data = json.loads(raw.decode("utf-8"))
                # content pode vir null (modelo de raciocínio que estourou o
                # limite de tokens pensando): antes o .strip() estourava um
                # AttributeError mostrado ao usuário como texto técnico.
                text = (((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
                if not text:
                    last_error = None
                    empty_reply = True
                    continue
                self.GROQ_MODEL = model  # atualiza modelo ativo
                return LLMResponse(text=text, backend=Backend.GROQ, model=model)
            except urllib.error.HTTPError as e:
                if e.code in (401,):
                    raise RuntimeError("Chave Groq inválida ou expirada. Gere uma nova em console.groq.com.") from None
                if e.code == 429:
                    # O limite da Groq é POR MODELO: o próximo da lista pode
                    # ter cota sobrando. Só desiste se todos estiverem no limite.
                    rate_limited = True
                    last_error = e
                    continue
                # 403 ou outro erro: tenta próximo modelo
                last_error = e
                continue

        if rate_limited and not empty_reply:
            raise RuntimeError("Limite de requisições Groq atingido em todos os modelos. Aguarde 1 minuto e tente novamente.")
        if empty_reply and last_error is None:
            raise RuntimeError("A Groq devolveu resposta vazia. Tente novamente.")
        raise RuntimeError(
            f"Nenhum modelo Groq disponível (último erro: {last_error.code if last_error else 'desconhecido'}).\n"
            "Verifique sua chave em console.groq.com."
        )
