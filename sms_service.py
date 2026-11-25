"""
Camada de Integração SMS — GESTOOR SIGN (Gestoor 360)
=====================================================
Provedor principal: Comtele
- Painel Novo (portal.comtele.com.br — Gateway V4 — PADRÃO):
    * Envio SMS: POST https://api.comtele.com.br/messages/sms/send
    * Rotas:     GET  https://api.comtele.com.br/routes
    * Header:    x-api-key: <COMTELE_API_KEY>
- Painel Antigo (sms.comtele.com.br — API v2 — Legado opcional):
    * Envio SMS: POST https://sms.comtele.com.br/api/v2/send
    * Header:    auth-key: <COMTELE_API_KEY>

Regras de segurança:
- O modo 'homologacao_local' é ESTRITAMENTE bloqueado em produção (Railway / FLASK_ENV=production).
- Nunca registra credenciais nem o código OTP em texto puro em logs persistentes.
- Valida rigorosamente telefones celulares brasileiros (DDD + 9 dígitos).
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


COMTELE_V4_SEND_URL = "https://api.comtele.com.br/messages/sms/send"
COMTELE_V4_ROUTES_URL = "https://api.comtele.com.br/routes"
COMTELE_LEGACY_SEND_URL = "https://sms.comtele.com.br/api/v2/send"


class SMSProviderError(Exception):
    """Erro operacional controlado no envio de SMS."""


@dataclass
class SMSResult:
    success: bool
    provider: str
    message_id: str
    status: str
    detail: str = ""
    homologacao_codigo: Optional[str] = None  # Preenchido APENAS em modo homologacao_local (dev)


def is_production_environment() -> bool:
    """Detecta se a aplicação está rodando em produção (Railway ou FLASK_ENV=production)."""
    return bool(
        os.getenv("RAILWAY_ENVIRONMENT")
        or os.getenv("RAILWAY_STATIC_URL")
        or (os.getenv("FLASK_ENV") or "").strip().lower() == "production"
        or (os.getenv("GESTOOR_ENV") or "").strip().lower() == "production"
    )


def normalizar_celular_br(telefone_raw: Optional[str]) -> Tuple[bool, str, str, str]:
    """
    Valida e normaliza um telefone celular brasileiro.
    Retorna: (valido, digits_11, e164, mensagem_erro)
    - digits_11: ex. '89999991234' (11 dígitos)
    - e164: ex. '+5589999991234' (formato internacional E.164)
    """
    digits = re.sub(r"\D", "", str(telefone_raw or ""))
    if digits.startswith("55") and len(digits) == 13:
        digits = digits[2:]
    if digits.startswith("0") and len(digits) == 12:
        digits = digits[1:]

    if len(digits) != 11:
        return (
            False,
            "",
            "",
            "Informe um número de celular válido com DDD e 9 dígitos (ex.: (89) 99999-1234).",
        )

    ddd = int(digits[:2])
    if ddd < 11 or ddd > 99:
        return False, "", "", "DDD inválido no número de celular informado."

    if digits[2] != "9":
        return (
            False,
            "",
            "",
            "O telefone precisa ser um celular válido (iniciado pelo dígito 9 após o DDD) para recebimento de SMS.",
        )

    if len(set(digits[2:])) == 1:
        return False, "", "", "Número de celular inválido (sequência repetida)."

    return True, digits, f"+55{digits}", ""


def mascarar_telefone(telefone_raw: Optional[str]) -> str:
    """
    Mascara parcialmente o número de celular para exibição segura (LGPD).
    Ex.: '89999123456' -> '(89) 9****-3456'
    """
    digits = re.sub(r"\D", "", str(telefone_raw or ""))
    if digits.startswith("55") and len(digits) >= 12:
        digits = digits[2:]
    if len(digits) == 11:
        return f"({digits[:2]}) {digits[2]}****-{digits[7:]}"
    if len(digits) == 10:
        return f"({digits[:2]}) ****-{digits[6:]}"
    if len(digits) >= 4:
        return f"****-{digits[-4:]}"
    return "Não informado"


def mascarar_cpf(cpf_raw: Optional[str]) -> str:
    """Mascara CPF no padrão LGPD: '***.456.789-**'."""
    digits = re.sub(r"\D", "", str(cpf_raw or ""))
    if len(digits) == 11:
        return f"***.{digits[3:6]}.{digits[6:9]}-**"
    return str(cpf_raw or "N/A")


class BaseSMSProvider:
    name: str = "base"

    def send(
        self,
        phone_digits_11: str,
        phone_e164: str,
        message: str,
        sender: str = "",
        custom_ref: str = "",
    ) -> SMSResult:
        raise NotImplementedError


class ComteleSMSProvider(BaseSMSProvider):
    """
    Adaptador oficial Comtele:
    - panel_mode='novo' (PADRÃO — portal.comtele.com.br / Gateway V4):
        POST https://api.comtele.com.br/messages/sms/send
        Header: x-api-key: <API_KEY>
        Body: {"receivers": [5589999991234], "contactGroups": [], "message": "...", "route": 17, "tag": "GESTOOR_SIGN", "custom": "..."}
    - panel_mode='antigo' (Legado — sms.comtele.com.br / API v2):
        POST https://sms.comtele.com.br/api/v2/send
        Header: auth-key: <API_KEY>
        Body: {"Sender": "GESTOOR360", "Receivers": "89999991234", "Content": "..."}
    """

    name = "comtele"

    def __init__(
        self,
        api_key: Optional[str] = None,
        panel_mode: Optional[str] = None,
        route_id: Optional[int] = None,
        base_url: Optional[str] = None,
        default_sender: Optional[str] = None,
    ):
        self.api_key = (api_key or os.getenv("COMTELE_API_KEY") or "").strip()
        mode_raw = (panel_mode or os.getenv("COMTELE_PANEL_MODE") or "novo").strip().lower()
        self.panel_mode = "antigo" if mode_raw in ("antigo", "legacy", "v2") else "novo"
        env_route = os.getenv("COMTELE_ROUTE_ID")
        try:
            self.route_id = int(route_id if route_id is not None else (env_route if env_route else 17))
        except (TypeError, ValueError):
            self.route_id = 17
        default_url = COMTELE_LEGACY_SEND_URL if self.panel_mode == "antigo" else COMTELE_V4_SEND_URL
        self.base_url = (base_url or os.getenv("COMTELE_BASE_URL") or default_url).strip()
        self.default_sender = (default_sender or os.getenv("COMTELE_SENDER") or "GESTOOR360").strip()

    def send(
        self,
        phone_digits_11: str,
        phone_e164: str,
        message: str,
        sender: str = "",
        custom_ref: str = "",
    ) -> SMSResult:
        if not self.api_key:
            raise SMSProviderError(
                "Chave de API Comtele não configurada. Informe a x-api-key em Configurações do Gestoor Sign ou na variável de ambiente COMTELE_API_KEY."
            )
        if requests is None:
            raise SMSProviderError("Biblioteca 'requests' não instalada no ambiente.")

        if self.panel_mode == "antigo":
            return self._send_legacy_v2(phone_digits_11, message, sender)
        return self._send_painel_novo_v4(phone_digits_11, message, sender, custom_ref)

    def _send_painel_novo_v4(self, phone_digits_11: str, message: str, sender: str, custom_ref: str) -> SMSResult:
        # Painel Novo espera número com DDI 55 (ex.: 5589999991234)
        receiver_num = int(f"55{phone_digits_11}")
        tag_val = re.sub(r"[^A-Za-z0-9_\-]", "", (sender or self.default_sender or "GESTOOR_SIGN"))[:30] or "GESTOOR_SIGN"
        payload: Dict[str, Any] = {
            "receivers": [receiver_num],
            "contactGroups": [],
            "message": message,
            "route": int(self.route_id or 17),
            "tag": tag_val,
        }
        if custom_ref:
            payload["custom"] = str(custom_ref)[:60]

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": self.api_key,
        }

        try:
            resp = requests.post(self.base_url, json=payload, headers=headers, timeout=15)
        except requests.Timeout:
            raise SMSProviderError("Tempo limite excedido ao comunicar com a API Comtele (Painel Novo).")
        except requests.RequestException as exc:
            raise SMSProviderError(f"Falha de rede ao conectar à Comtele: {exc}")

        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text[:300]}

        has_error = bool(data.get("hasError")) if isinstance(data, dict) else True
        if resp.status_code in (200, 201) and isinstance(data, dict) and not has_error:
            obj = data.get("object")
            req_uid = None
            if isinstance(obj, dict):
                req_uid = obj.get("id") or obj.get("requestUniqueId") or obj.get("messageId") or obj.get("batchId")
            elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                req_uid = obj[0].get("id") or obj[0].get("requestUniqueId") or obj[0].get("messageId")
            elif isinstance(obj, (str, int)) and str(obj).strip():
                req_uid = str(obj).strip()
            if not req_uid:
                req_uid = f"comtele-v4-{uuid.uuid4().hex[:12]}"
            return SMSResult(
                success=True,
                provider="comtele",
                message_id=str(req_uid)[:115],
                status="ENVIADO",
                detail=str(data.get("message") or "SMS aceito pela Comtele (Painel Novo V4)."),
            )

        err_parts: List[str] = []
        if isinstance(data, dict):
            if data.get("message"):
                err_parts.append(str(data["message"]))
            if isinstance(data.get("errors"), list) and data["errors"]:
                err_parts.extend(str(e) for e in data["errors"] if e)
            if not err_parts and data.get("raw"):
                err_parts.append(str(data["raw"]))
        err_msg = " | ".join(err_parts) or "erro desconhecido"
        raise SMSProviderError(f"Comtele (Painel Novo) recusou o envio (HTTP {resp.status_code}): {err_msg}")

    def _send_legacy_v2(self, phone_digits_11: str, message: str, sender: str) -> SMSResult:
        payload = {
            "Sender": (sender or self.default_sender or "GESTOOR360")[:20],
            "Receivers": phone_digits_11,
            "Content": message,
        }
        headers = {
            "Content-Type": "application/json",
            "auth-key": self.api_key,
        }
        try:
            resp = requests.post(self.base_url, json=payload, headers=headers, timeout=15)
        except requests.Timeout:
            raise SMSProviderError("Tempo limite excedido ao comunicar com a API da Comtele (Painel Antigo).")
        except requests.RequestException as exc:
            raise SMSProviderError(f"Falha de rede ao conectar à Comtele: {exc}")

        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text[:300]}

        if resp.status_code in (200, 201) and isinstance(data, dict) and data.get("Success", True):
            obj = data.get("Object") if isinstance(data.get("Object"), dict) else {}
            req_uid = (
                obj.get("requestUniqueId")
                or data.get("requestUniqueId")
                or data.get("Message")
                or f"comtele-v2-{uuid.uuid4().hex[:12]}"
            )
            return SMSResult(
                success=True,
                provider="comtele",
                message_id=str(req_uid)[:115],
                status="ENVIADO",
                detail=str(data.get("Message") or "SMS aceito pela Comtele (Painel Antigo v2)."),
            )

        err_msg = ""
        if isinstance(data, dict):
            err_msg = str(data.get("Message") or data.get("message") or data.get("error") or data.get("raw") or "")
        raise SMSProviderError(f"Comtele (Painel Antigo) recusou o envio (HTTP {resp.status_code}): {err_msg or 'erro desconhecido'}")


def listar_rotas_comtele(api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Consulta as rotas SMS disponíveis na conta do Painel Novo Comtele (GET https://api.comtele.com.br/routes).
    Utilizado na tela de configurações para validar a x-api-key e selecionar o ID da rota ativa.
    """
    key = (api_key or os.getenv("COMTELE_API_KEY") or "").strip()
    if not key:
        raise SMSProviderError("Informe a Chave de API (x-api-key) da Comtele para consultar as rotas.")
    if requests is None:
        raise SMSProviderError("Biblioteca 'requests' não instalada no ambiente.")

    try:
        resp = requests.get(
            COMTELE_V4_ROUTES_URL,
            headers={"x-api-key": key, "Accept": "application/json"},
            timeout=15,
        )
    except requests.Timeout:
        raise SMSProviderError("Tempo limite excedido ao consultar rotas na API Comtele.")
    except requests.RequestException as exc:
        raise SMSProviderError(f"Erro de conexão ao consultar rotas Comtele: {exc}")

    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text[:300]}

    if resp.status_code != 200 or (isinstance(data, dict) and data.get("hasError")):
        err = ""
        if isinstance(data, dict):
            err = str(data.get("message") or data.get("errors") or data.get("raw") or "")
        raise SMSProviderError(f"Falha ao autenticar/consultar rotas Comtele (HTTP {resp.status_code}): {err or 'verifique sua x-api-key'}")

    raw_list = data.get("object") if isinstance(data, dict) else (data if isinstance(data, list) else [])
    rotas: List[Dict[str, Any]] = []
    for item in raw_list or []:
        if not isinstance(item, dict):
            continue
        rotas.append(
            {
                "id": item.get("id"),
                "displayName": item.get("displayName") or f"Rota {item.get('id')}",
                "productName": item.get("productName") or "SMS",
                "farePrice": item.get("farePrice"),
            }
        )
    return rotas


class TwilioSMSProvider(BaseSMSProvider):
    """Adaptador alternativo para Twilio Programmable Messaging."""

    name = "twilio"

    def __init__(self):
        self.account_sid = (os.getenv("TWILIO_ACCOUNT_SID") or "").strip()
        self.auth_token = (os.getenv("TWILIO_AUTH_TOKEN") or "").strip()
        self.from_number = (os.getenv("TWILIO_FROM_NUMBER") or "").strip()

    def send(self, phone_digits_11: str, phone_e164: str, message: str, sender: str = "", custom_ref: str = "") -> SMSResult:
        if not (self.account_sid and self.auth_token and self.from_number):
            raise SMSProviderError("Credenciais Twilio (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER) incompletas.")
        if requests is None:
            raise SMSProviderError("Biblioteca 'requests' não instalada no ambiente.")

        url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
        try:
            resp = requests.post(
                url,
                data={"From": self.from_number, "To": phone_e164, "Body": message},
                auth=(self.account_sid, self.auth_token),
                timeout=15,
            )
            data = resp.json()
        except Exception as exc:
            raise SMSProviderError(f"Falha ao enviar SMS via Twilio: {exc}")

        if resp.status_code in (200, 201) and data.get("sid"):
            return SMSResult(
                success=True,
                provider=self.name,
                message_id=str(data["sid"])[:115],
                status="ENVIADO",
                detail=str(data.get("status") or "queued"),
            )
        raise SMSProviderError(f"Twilio recusou envio (HTTP {resp.status_code}): {data.get('message', 'erro')}")


class ZenviaSMSProvider(BaseSMSProvider):
    """Adaptador alternativo para Zenvia SMS API v2."""

    name = "zenvia"

    def __init__(self):
        self.api_token = (os.getenv("ZENVIA_API_TOKEN") or "").strip()
        self.from_alias = (os.getenv("ZENVIA_FROM") or "gestoor360").strip()

    def send(self, phone_digits_11: str, phone_e164: str, message: str, sender: str = "", custom_ref: str = "") -> SMSResult:
        if not self.api_token:
            raise SMSProviderError("Credencial ZENVIA_API_TOKEN não configurada.")
        if requests is None:
            raise SMSProviderError("Biblioteca 'requests' não instalada no ambiente.")

        payload = {
            "from": sender or self.from_alias,
            "to": f"55{phone_digits_11}",
            "contents": [{"type": "text", "text": message}],
        }
        try:
            resp = requests.post(
                "https://api.zenvia.com/v2/channels/sms/messages",
                json=payload,
                headers={"X-API-TOKEN": self.api_token, "Content-Type": "application/json"},
                timeout=15,
            )
            data = resp.json()
        except Exception as exc:
            raise SMSProviderError(f"Falha ao enviar SMS via Zenvia: {exc}")

        if resp.status_code in (200, 201) and data.get("id"):
            return SMSResult(
                success=True,
                provider=self.name,
                message_id=str(data["id"])[:115],
                status="ENVIADO",
                detail="SMS aceito pela Zenvia.",
            )
        raise SMSProviderError(f"Zenvia recusou envio (HTTP {resp.status_code}): {data.get('message', 'erro')}")


class HomologacaoLocalSMSProvider(BaseSMSProvider):
    """
    Provedor simulado exclusivo para ambiente local de desenvolvimento/homologação.
    BLOQUEADO automaticamente em produção (Railway / FLASK_ENV=production).
    """

    name = "homologacao_local"

    def send(self, phone_digits_11: str, phone_e164: str, message: str, sender: str = "", custom_ref: str = "") -> SMSResult:
        if is_production_environment():
            raise SMSProviderError(
                "O modo 'homologacao_local' é proibido em ambiente de produção. Configure a API Comtele (x-api-key)."
            )
        msg_id = f"SIM-{uuid.uuid4().hex[:14].upper()}"
        return SMSResult(
            success=True,
            provider=self.name,
            message_id=msg_id,
            status="SIMULADO_HOMOLOGACAO",
            detail="Envio simulado em ambiente de homologação local (sem disparo real de operadora).",
        )


def resolve_provider_name(config_provider: Optional[str] = None) -> str:
    """Resolve qual provedor SMS usar (prioriza variável de ambiente SMS_PROVIDER, depois configuração municipal, padrão Comtele)."""
    env_prov = (os.getenv("SMS_PROVIDER") or "").strip().lower()
    cfg_prov = (config_provider or "").strip().lower()
    chosen = env_prov or cfg_prov or "comtele"
    if chosen not in ("comtele", "twilio", "zenvia", "homologacao_local"):
        chosen = "comtele"
    if chosen == "homologacao_local" and is_production_environment():
        return "comtele"
    return chosen


def get_sms_provider(
    provider_name: Optional[str] = None,
    comtele_api_key: Optional[str] = None,
    comtele_panel_mode: Optional[str] = None,
    comtele_route_id: Optional[int] = None,
) -> BaseSMSProvider:
    name = resolve_provider_name(provider_name)
    if name == "comtele":
        return ComteleSMSProvider(
            api_key=comtele_api_key,
            panel_mode=comtele_panel_mode,
            route_id=comtele_route_id,
        )
    if name == "twilio":
        return TwilioSMSProvider()
    if name == "zenvia":
        return ZenviaSMSProvider()
    if name == "homologacao_local":
        return HomologacaoLocalSMSProvider()
    return ComteleSMSProvider(
        api_key=comtele_api_key,
        panel_mode=comtele_panel_mode,
        route_id=comtele_route_id,
    )


def enviar_sms_otp(
    telefone_raw: str,
    codigo_otp: str,
    num_contrato: str,
    municipio_nome: str = "Prefeitura Municipal",
    provider_name: Optional[str] = None,
    sender: str = "GESTOOR360",
    expiracao_minutos: int = 5,
    comtele_api_key: Optional[str] = None,
    comtele_panel_mode: Optional[str] = None,
    comtele_route_id: Optional[int] = None,
) -> SMSResult:
    """
    Formata a mensagem institucional (<= 160 caracteres para 1 crédito SMS) e envia o OTP ao celular do servidor.
    Retorna SMSResult (nunca armazena o código em texto puro em disco ou banco).
    """
    ok, digits_11, e164, err = normalizar_celular_br(telefone_raw)
    if not ok:
        raise SMSProviderError(err)

    provider = get_sms_provider(
        provider_name=provider_name,
        comtele_api_key=comtele_api_key,
        comtele_panel_mode=comtele_panel_mode,
        comtele_route_id=comtele_route_id,
    )
    mun_curto = (municipio_nome or "Gestoor360").strip()[:24]
    mensagem = (
        f"GESTOOR SIGN ({mun_curto}): Codigo {codigo_otp} p/ assinar Contrato {num_contrato}. "
        f"Valido {expiracao_minutos}min. Informe ao RH somente apos concordar."
    )

    result = provider.send(
        phone_digits_11=digits_11,
        phone_e164=e164,
        message=mensagem,
        sender=sender,
        custom_ref=f"GSIGN-{num_contrato}"[:60],
    )

    # Apenas em ambiente local de homologação (nunca em produção), retorna o código na resposta imediata para teste
    if provider.name == "homologacao_local" and not is_production_environment():
        result.homologacao_codigo = codigo_otp

    return result


def enviar_sms_teste(
    telefone_raw: str,
    municipio_nome: str = "Gestoor360",
    comtele_api_key: Optional[str] = None,
    comtele_panel_mode: str = "novo",
    comtele_route_id: int = 17,
    sender: str = "GESTOOR360",
) -> SMSResult:
    """Envia um SMS real de teste via Comtele para validar chave x-api-key e rota antes de operar."""
    ok, digits_11, e164, err = normalizar_celular_br(telefone_raw)
    if not ok:
        raise SMSProviderError(err)
    provider = ComteleSMSProvider(
        api_key=comtele_api_key,
        panel_mode=comtele_panel_mode,
        route_id=comtele_route_id,
        default_sender=sender,
    )
    mun_curto = (municipio_nome or "Gestoor360").strip()[:28]
    msg = f"GESTOOR SIGN ({mun_curto}): Integracao Comtele validada com sucesso!"
    return provider.send(
        phone_digits_11=digits_11,
        phone_e164=e164,
        message=msg,
        sender=sender,
        custom_ref="GESTOOR-TESTE-SMS",
    )


def diagnostico_provedor_sms(
    config_provider: Optional[str] = None,
    has_db_comtele_key: bool = False,
    comtele_panel_mode: Optional[str] = None,
    comtele_route_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Retorna status operacional do provedor SMS sem expor segredos."""
    prod = is_production_environment()
    provider = resolve_provider_name(config_provider)
    env_comtele_ok = bool((os.getenv("COMTELE_API_KEY") or "").strip())
    comtele_ok = bool(has_db_comtele_key or env_comtele_ok)
    panel_mode = (comtele_panel_mode or os.getenv("COMTELE_PANEL_MODE") or "novo").strip().lower()
    panel_label = "Painel Novo (x-api-key)" if panel_mode != "antigo" else "Painel Antigo (auth-key)"
    route_val = comtele_route_id or int(os.getenv("COMTELE_ROUTE_ID") or 17)

    twilio_ok = bool(
        (os.getenv("TWILIO_ACCOUNT_SID") or "").strip()
        and (os.getenv("TWILIO_AUTH_TOKEN") or "").strip()
        and (os.getenv("TWILIO_FROM_NUMBER") or "").strip()
    )
    zenvia_ok = bool((os.getenv("ZENVIA_API_TOKEN") or "").strip())

    configurado = False
    detalhe = ""
    if provider == "comtele":
        configurado = comtele_ok
        origem_chave = "salva no painel" if has_db_comtele_key else "variável COMTELE_API_KEY"
        detalhe = (
            f"Comtele {panel_label} pronta ({origem_chave} • Rota {route_val})."
            if comtele_ok
            else f"Informe sua x-api-key da Comtele ({panel_label}) nas Configurações do Gestoor Sign ou em COMTELE_API_KEY."
        )
    elif provider == "twilio":
        configurado = twilio_ok
        detalhe = "Twilio configurado." if twilio_ok else "Credenciais Twilio pendentes."
    elif provider == "zenvia":
        configurado = zenvia_ok
        detalhe = "Zenvia configurada." if zenvia_ok else "Credencial ZENVIA_API_TOKEN pendente."
    elif provider == "homologacao_local":
        configurado = not prod
        detalhe = (
            "Modo de homologação local ativo (simulação de SMS apenas para testes locais)."
            if not prod
            else "Modo homologação bloqueado em produção."
        )

    return {
        "provider": provider,
        "ambiente_producao": prod,
        "configurado": configurado,
        "comtele_pronto": comtele_ok,
        "comtele_has_db_key": bool(has_db_comtele_key),
        "comtele_has_env_key": env_comtele_ok,
        "comtele_panel_mode": panel_mode,
        "comtele_route_id": route_val,
        "detalhe": detalhe,
    }
