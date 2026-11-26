"""
Motor de Domínio — GESTOOR SIGN (Assinatura Eletrônica Presencial por SMS)
==========================================================================
Gerencia o ciclo de vida completo das 6 etapas presenciais:
1. Cadastro / Conferência do Servidor (Nome, CPF, Celular confirmado)
2. Contrato Gerado no Gestoor360 (exclusivo para contratos internos)
3. Início da Assinatura (presença confirmada + conferência integral + congelamento PDF base + SHA-256)
4. Autenticação OTP por SMS (CSPRNG + HMAC-SHA256 sem texto puro, TTL, limite de tentativas, cooldown, bloqueio)
5. Manifestação Expressa de Vontade realizada diretamente pelo Servidor (dupla barreira anti-marcação pelo técnico)
6. Finalização & Selo (PDF final assinado + Relatório de Evidências + QR Code + SHA-256 + Arquivamento Automático no GED)

Conformidade jurídica:
- Lei nº 14.063/2020 (classificação explícita como Assinatura Eletrônica Simples)
- MP nº 2.200-2/2001 (art. 10, § 2º)
- LGPD — Lei nº 13.709/2018 (mascaramento, minimização, cifragem em repouso, trilha de auditoria)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pytz
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image as PILImage

import gestoor_sign_pdf
import sms_service

# Texto legal obrigatório da Etapa 5 (exato conforme especificação)
TEXTO_MANIFESTACAO_VONTADE = (
    "Declaro que tive acesso ao conteúdo integral deste contrato, que pude realizar sua leitura "
    "e que concordo com os seus termos. Confirmo minha intenção de assiná-lo eletronicamente."
)

# Status do Contrato no ciclo Gestoor Sign
STATUS_AGUARDANDO = "AGUARDANDO_ASSINATURA"
STATUS_PENDENTE = "ASSINATURA_PENDENTE"
STATUS_FALHA_AUTH = "FALHA_AUTENTICACAO"
STATUS_ASSINADO = "ASSINADO_ELETRONICAMENTE"
STATUS_CANCELADO = "CANCELADO"
STATUS_SUBSTITUIDO = "SUBSTITUIDO"

# Status internos da Sessão de Assinatura (máquina de estados das 6 etapas)
SESSAO_INICIADA = "INICIADA"
SESSAO_CONFERIDA = "CONTRATO_CONFERIDO"
SESSAO_SMS_ENVIADO = "CODIGO_ENVIADO"
SESSAO_SMS_VALIDADO = "CODIGO_VALIDADO"
SESSAO_CONCORDANCIA = "CONCORDANCIA_CONFIRMADA"
SESSAO_ASSINADA = "ASSINADO_ELETRONICAMENTE"
SESSAO_FALHA = "FALHA_AUTENTICACAO"
SESSAO_CANCELADA = "CANCELADO"

# Modalidades Jurídicas (Lei nº 14.063/2020)
MODALIDADE_SIMPLES = "SIMPLES"
MODALIDADE_AVANCADA = "AVANCADA"
MODALIDADE_QUALIFICADA = "QUALIFICADA"

MODALIDADE_SMS_CODIGO = "ASSINATURA_ELETRONICA_SIMPLES"
MODALIDADE_SMS_LABEL = "Assinatura Eletrônica Simples (SMS Presencial — Lei nº 14.063/2020)"

STATUS_LABELS = {
    STATUS_AGUARDANDO: "Aguardando Assinatura",
    STATUS_PENDENTE: "Assinatura Pendente",
    STATUS_FALHA_AUTH: "Falha de Autenticação",
    STATUS_ASSINADO: "Assinado Eletronicamente",
    STATUS_CANCELADO: "Cancelado",
    STATUS_SUBSTITUIDO: "Substituído (Nova Versão)",
}

TIPOS_CONTRATO_PADRAO = [
    ("TEMPORARIO", "Contrato Temporário (Art. 37, IX CF)"),
    ("COMISSIONADO", "Termo / Contrato Comissionado"),
    ("ESTAGIO", "Termo de Compromisso de Estágio"),
    ("ADITIVO", "Termo Aditivo Contratual"),
    ("OUTRO", "Outro Contrato Administrativo de RH"),
]

LOCAL_MODOS_VALIDOS = {
    "BLOCO_CONTRATADO": "Folha de Assinaturas — Campo do Contratado (Pág. 4)",
    "BLOCO_CONTRATADO_E_EXTRATO": "Folha de Assinaturas (Pág. 4) + Extrato (Pág. 5)",
    "RODAPE_TODAS_PAGINAS": "Folha de Assinaturas (Pág. 4) + Rubrica no Rodapé de Todas as Páginas",
    "POSICAO_PERSONALIZADA": "Posição Personalizada Selecionada no Contrato",
}


def normalizar_local_assinatura(raw: Any) -> Dict[str, Any]:
    """Valida e normaliza a configuração de posicionamento visual da assinatura eletrônica no contrato."""
    default = {
        "modo": "BLOCO_CONTRATADO",
        "pagina": 4,
        "x_pct": 50.0,
        "y_pct": 66.0,
        "descricao": LOCAL_MODOS_VALIDOS["BLOCO_CONTRATADO"],
    }
    if not raw:
        return default
    data = raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except Exception:
            return default
    if not isinstance(data, dict):
        return default

    modo = str(data.get("modo") or "BLOCO_CONTRATADO").strip().upper()
    if modo not in LOCAL_MODOS_VALIDOS:
        modo = "BLOCO_CONTRATADO"

    try:
        pagina = int(data.get("pagina") or 4)
    except Exception:
        pagina = 4
    pagina = max(1, min(pagina, 5))

    try:
        x_pct = float(data.get("x_pct") if data.get("x_pct") is not None else 50.0)
    except Exception:
        x_pct = 50.0
    x_pct = round(max(10.0, min(x_pct, 90.0)), 2)

    try:
        y_pct = float(data.get("y_pct") if data.get("y_pct") is not None else 66.0)
    except Exception:
        y_pct = 66.0
    y_pct = round(max(10.0, min(y_pct, 90.0)), 2)

    desc = LOCAL_MODOS_VALIDOS[modo]
    if modo == "POSICAO_PERSONALIZADA":
        desc = f"Posição Personalizada — Página {pagina} (X: {x_pct:.0f}%, Y: {y_pct:.0f}%)"

    return {
        "modo": modo,
        "pagina": pagina,
        "x_pct": x_pct,
        "y_pct": y_pct,
        "descricao": desc,
    }


class GestoorSignError(Exception):
    """Erro de regra de negócio do Gestoor Sign."""

    def __init__(self, message: str, status_code: int = 400, extra: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.extra = extra or {}


def now_utc() -> datetime:
    return datetime.utcnow()


def format_brt(dt: Optional[datetime]) -> str:
    if not dt:
        return "—"
    tz_brt = pytz.timezone("America/Sao_Paulo")
    if dt.tzinfo is None:
        dt_utc = pytz.utc.localize(dt)
    else:
        dt_utc = dt.astimezone(pytz.utc)
    return dt_utc.astimezone(tz_brt).strftime("%d/%m/%Y às %H:%M:%S")


def _derive_aes_key(secret_key: str) -> bytes:
    return hashlib.sha256(f"gestoor-sign-aes-v1:{secret_key}".encode("utf-8")).digest()


def cifrar_dado_sensivel(valor: str, secret_key: str) -> str:
    """Cifra dados pessoais (ex.: telefone E.164) em repouso com AES-256-GCM."""
    if not valor:
        return ""
    key = _derive_aes_key(secret_key)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, valor.encode("utf-8"), None)
    return "encv1:" + base64.b64encode(nonce + ct).decode("ascii")


def decifrar_dado_sensivel(payload: str, secret_key: str) -> str:
    if not payload or not payload.startswith("encv1:"):
        return ""
    try:
        raw = base64.b64decode(payload[6:])
        nonce, ct = raw[:12], raw[12:]
        key = _derive_aes_key(secret_key)
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except Exception:
        return ""


def obter_comtele_api_key(config, secret_key: str) -> str:
    """Resolve a API Key Comtele (prioriza chave municipal cifrada no banco; fallback para variável COMTELE_API_KEY)."""
    enc = getattr(config, "comtele_api_key_enc", None) if config else None
    if enc:
        dec = decifrar_dado_sensivel(enc, secret_key)
        if dec:
            return dec.strip()
    return (os.getenv("COMTELE_API_KEY") or "").strip()


MAX_ASSINATURA_IMG_BYTES = 2 * 1024 * 1024  # 2 MB


def validar_imagem_assinatura_upload(file_storage) -> Tuple[bool, Optional[str], str]:
    """
    Valida, otimiza e converte uma imagem de assinatura (PNG/JPG/WebP) para data URI PNG base64.
    Preserva transparência (RGBA) quando presente e limita dimensões a 800x320px para nitidez A4.
    """
    if not file_storage or not getattr(file_storage, "filename", ""):
        return True, None, ""

    raw = file_storage.read()
    if not raw:
        return False, None, "O arquivo de assinatura enviado está vazio."
    if len(raw) > MAX_ASSINATURA_IMG_BYTES:
        return False, None, "A imagem da assinatura excede o tamanho máximo de 2 MB."

    try:
        with PILImage.open(io.BytesIO(raw)) as img:
            if (img.format or "").upper() not in ("PNG", "JPEG", "JPG", "WEBP"):
                return False, None, "Formato de assinatura inválido. Use PNG, JPG ou WebP."
            # Converte para RGBA para preservar transparência (ou RGB limpo)
            if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                img_proc = img.convert("RGBA")
            else:
                img_proc = img.convert("RGB")
            img_proc.thumbnail((800, 320), PILImage.Resampling.LANCZOS)
            out = io.BytesIO()
            img_proc.save(out, format="PNG", optimize=True)
            b64 = base64.b64encode(out.getvalue()).decode("ascii")
            return True, f"data:image/png;base64,{b64}", ""
    except Exception:
        return False, None, "Não foi possível ler a imagem da assinatura. Envie um arquivo PNG, JPG ou WebP válido."


def sha256_texto(texto: str, pepper: str = "") -> str:
    return hashlib.sha256(f"{pepper}:{texto}".encode("utf-8")).hexdigest()


def gerar_codigo_otp(tamanho: int = 6) -> str:
    """Gera código OTP numérico criptograficamente seguro (CSPRNG)."""
    tam = max(6, min(int(tamanho or 6), 8))
    limite = 10 ** tam
    return f"{secrets.randbelow(limite):0{tam}d}"


def hash_otp(codigo: str, salt: str, secret_key: str) -> str:
    """Calcula HMAC-SHA256 do OTP com pepper do servidor + salt individual. Nunca armazena texto puro."""
    chave = f"gestoor-sign-otp-v1:{secret_key}:{salt}".encode("utf-8")
    return hmac.new(chave, str(codigo).strip().encode("utf-8"), hashlib.sha256).hexdigest()


def verificar_otp_hash(codigo_digitado: str, salt: str, expected_hash: str, secret_key: str) -> bool:
    calculado = hash_otp(codigo_digitado, salt, secret_key)
    return hmac.compare_digest(calculado, str(expected_hash or ""))


def gerar_codigo_validacao(ano: Optional[int] = None) -> str:
    """Gera código único de verificação pública: GS360-AAAA-XXXX-XXXX-XXXX."""
    a = int(ano or datetime.now().year)
    p1 = secrets.token_hex(2).upper()
    p2 = secrets.token_hex(2).upper()
    p3 = secrets.token_hex(2).upper()
    return f"GS360-{a}-{p1}-{p2}-{p3}"


def calcular_etapa_atual(assinatura) -> int:
    """Retorna índice de progresso de 1 a 6 conforme o estado atual da sessão."""
    if not assinatura:
        return 1
    st = assinatura.status or SESSAO_INICIADA
    if st == SESSAO_ASSINADA:
        return 6
    if st == SESSAO_CONCORDANCIA:
        return 5
    if st == SESSAO_SMS_VALIDADO:
        return 4
    if st == SESSAO_SMS_ENVIADO:
        return 3
    if st == SESSAO_CONFERIDA:
        return 2
    if st == SESSAO_FALHA:
        return 3
    return 1


def obter_ou_criar_config_municipio(db, models: Dict[str, Any], municipio_id: Optional[int]):
    """Garante existência de ConfiguracaoGestoorSign para o município."""
    ConfiguracaoGestoorSign = models["ConfiguracaoGestoorSign"]
    Municipio = models["Municipio"]

    if not municipio_id:
        mun = Municipio.query.order_by(Municipio.id.asc()).first()
        municipio_id = mun.id if mun else None
    if not municipio_id:
        raise GestoorSignError("Nenhum município configurado no sistema.", 500)

    cfg = ConfiguracaoGestoorSign.query.filter_by(municipio_id=int(municipio_id)).first()
    if not cfg:
        regras_default = {
            "TEMPORARIO": MODALIDADE_SIMPLES,
            "COMISSIONADO": MODALIDADE_SIMPLES,
            "ESTAGIO": MODALIDADE_SIMPLES,
            "ADITIVO": MODALIDADE_SIMPLES,
            "OUTRO": MODALIDADE_SIMPLES,
        }
        cfg = ConfiguracaoGestoorSign(
            municipio_id=int(municipio_id),
            modalidade_minima_padrao=MODALIDADE_SIMPLES,
            regras_modalidade_json=json.dumps(regras_default, ensure_ascii=False),
            ato_normativo_referencia="Lei Federal nº 14.063/2020 e MP nº 2.200-2/2001 (pendente de regulamentação municipal)",
            validacao_juridica_status="PENDENTE",
            otp_tamanho=6,
            otp_expiracao_segundos=300,
            otp_max_tentativas=3,
            otp_max_reenvios=3,
            otp_cooldown_reenvio_segundos=60,
            bloqueio_minutos=30,
            sms_provider="comtele",
            sms_remetente="GESTOOR360",
            arquivar_ged_automatico=True,
        )
        db.session.add(cfg)
        db.session.commit()
    return cfg


def verificar_modalidade_minima(config, tipo_contrato: Optional[str]) -> Tuple[bool, str, str]:
    """
    Verifica se a regulamentação municipal permite Assinatura Eletrônica Simples (SMS)
    para o tipo de contrato informado.
    Retorna: (permitido_sms, modalidade_exigida, mensagem)
    """
    tipo = (tipo_contrato or "TEMPORARIO").strip().upper()
    modalidade_exigida = (config.modalidade_minima_padrao or MODALIDADE_SIMPLES).strip().upper()
    try:
        regras = json.loads(config.regras_modalidade_json or "{}")
        if isinstance(regras, dict) and tipo in regras:
            modalidade_exigida = str(regras[tipo]).strip().upper()
    except Exception:
        pass

    if modalidade_exigida == MODALIDADE_SIMPLES:
        return True, MODALIDADE_SIMPLES, "Permitida Assinatura Eletrônica Simples por SMS presencial."

    return (
        False,
        modalidade_exigida,
        (
            f"Bloqueado pela regulamentação municipal: contratos do tipo '{tipo}' exigem "
            f"Assinatura Eletrônica {modalidade_exigida}. A autenticação isolada por SMS é classificada "
            f"exclusivamente como Assinatura Eletrônica SIMPLES (Lei nº 14.063/2020) e não pode substituir "
            f"assinatura {modalidade_exigida}."
        ),
    )


def registrar_evento_assinatura(
    db,
    models: Dict[str, Any],
    assinatura,
    tipo_evento: str,
    descricao: str,
    ator_tipo: str = "TECNICO_RH",
    usuario_id: Optional[int] = None,
    req_info: Optional[Dict[str, str]] = None,
    detalhes: Optional[Dict[str, Any]] = None,
):
    """Insere evento append-only com hash encadeado (hash chain) por assinatura."""
    AssinaturaEvento = models["AssinaturaEvento"]
    req_info = req_info or {}
    detalhes_str = json.dumps(detalhes or {}, ensure_ascii=False, sort_keys=True)
    agora = now_utc()

    ultimo = (
        AssinaturaEvento.query.filter_by(assinatura_id=assinatura.id)
        .order_by(AssinaturaEvento.id.desc())
        .first()
    )
    hash_anterior = ultimo.hash_evento_atual if ultimo else ("0" * 64)
    base_chain = (
        f"{hash_anterior}|{assinatura.id}|{assinatura.contrato_id}|{tipo_evento}|"
        f"{agora.isoformat()}|{ator_tipo}|{usuario_id or ''}|{descricao}|{detalhes_str}"
    )
    hash_atual = hashlib.sha256(base_chain.encode("utf-8")).hexdigest()

    ev = AssinaturaEvento(
        assinatura_id=assinatura.id,
        contrato_id=assinatura.contrato_id,
        municipio_id=assinatura.municipio_id,
        tipo_evento=tipo_evento,
        descricao=str(descricao)[:490],
        ator_tipo=ator_tipo,
        usuario_id=usuario_id,
        ip_origem=(req_info.get("ip") or "")[:50] or None,
        user_agent=(req_info.get("ua") or "")[:250] or None,
        detalhes_json=detalhes_str,
        data_hora=agora,
        hash_evento_anterior=hash_anterior,
        hash_evento_atual=hash_atual,
    )
    db.session.add(ev)
    return ev


def montar_contexto_contrato_pdf(contrato, db, models: Dict[str, Any], format_data_extenso, format_rem_rs) -> Dict[str, Any]:
    """Constrói o dicionário completo e canônico de dados do contrato para geração determinística de PDF."""
    Secretaria = models["Secretaria"]
    Municipio = models["Municipio"]
    ConfiguracaoGestoorSign = models.get("ConfiguracaoGestoorSign")

    sec = db.session.get(Secretaria, contrato.secretaria_id) if contrato.secretaria_id else None
    mun_id = contrato.municipio_id or (sec.municipio_id if sec else None)
    mun = db.session.get(Municipio, mun_id) if mun_id else Municipio.query.order_by(Municipio.id.asc()).first()
    cfg_sign = None
    if ConfiguracaoGestoorSign and mun:
        cfg_sign = ConfiguracaoGestoorSign.query.filter_by(municipio_id=mun.id).first()

    dt_ass = contrato.dt_assinatura or contrato.dt_inicio or (contrato.funcionario.dt_inicio if contrato.funcionario else None)
    mun_nome_raw = mun.nome if mun else "Município de Valença do Piauí"
    mun_cidade = re.sub(r"^Munic[ií]pio\s+de\s+", "", mun_nome_raw, flags=re.IGNORECASE).strip() or "Valença do Piauí"

    return {
        "id": contrato.id,
        "num_contrato": contrato.num_contrato,
        "versao": int(getattr(contrato, "versao", 1) or 1),
        "ano_exercicio": contrato.ano_exercicio,
        "tipo_contrato": getattr(contrato, "tipo_contrato", None) or "TEMPORARIO",
        "municipio_nome": mun_nome_raw,
        "municipio_cidade": mun_cidade,
        "municipio_uf": (mun.uf if mun and mun.uf else "PI"),
        "secretaria_nome": (sec.nome if sec and sec.nome else "SECRETARIA DE EDUCAÇÃO"),
        "secretaria_cnpj": (sec.cnpj if sec and sec.cnpj else (mun.cnpj if mun and mun.cnpj else "06.095.146/0001-44")),
        "secretaria_endereco": (
            sec.endereco
            if sec and sec.endereco
            else (mun.endereco if mun and mun.endereco else "Rua Epaminondas Nogueira, nº 1425, Bairro São Francisco, Valença do Piauí-PI")
        ),
        "contratado_nome": contrato.contratado_nome or "",
        "contratado_cpf": contrato.contratado_cpf or "",
        "contratado_rg": contrato.contratado_rg or "",
        "contratado_nacionalidade": contrato.contratado_nacionalidade or "brasileiro(a)",
        "contratado_naturalidade": contrato.contratado_naturalidade or "piauiense",
        "contratado_estado_civil": contrato.contratado_estado_civil or "solteiro(a)",
        "contratado_endereco": contrato.contratado_endereco or "",
        "funcao_nome": contrato.funcao_nome or "",
        "remuneracao": contrato.remuneracao or "",
        "remuneracao_formatada": format_rem_rs(contrato.remuneracao),
        "remuneracao_extenso": contrato.remuneracao_extenso or "",
        "jornada_trabalho": contrato.jornada_trabalho or "",
        "dt_inicio_extenso": format_data_extenso(contrato.dt_inicio),
        "dt_termino_extenso": format_data_extenso(contrato.dt_termino),
        "dt_assinatura_extenso": format_data_extenso(dt_ass),
        "dt_inicio_formatada": contrato.dt_inicio.strftime("%d/%m/%Y") if contrato.dt_inicio else "",
        "dt_termino_formatada": contrato.dt_termino.strftime("%d/%m/%Y") if contrato.dt_termino else "",
        "dt_assinatura_formatada": dt_ass.strftime("%d/%m/%Y") if dt_ass else "",
        "representante_nome": contrato.representante_nome or "",
        "representante_cargo": contrato.representante_cargo or "",
        "representante_rg_cpf": contrato.representante_rg_cpf or "",
        "representante_endereco": contrato.representante_endereco or "",
        # Assinaturas fixas configuradas no município (Secretaria + 2 Testemunhas)
        "assinatura_secretaria_b64": getattr(cfg_sign, "assinatura_secretaria_b64", None) if cfg_sign else None,
        "testemunha1_nome": (getattr(cfg_sign, "testemunha1_nome", None) or "").strip() if cfg_sign else "",
        "testemunha1_cpf": (getattr(cfg_sign, "testemunha1_cpf", None) or "").strip() if cfg_sign else "",
        "testemunha1_assinatura_b64": getattr(cfg_sign, "testemunha1_assinatura_b64", None) if cfg_sign else None,
        "testemunha2_nome": (getattr(cfg_sign, "testemunha2_nome", None) or "").strip() if cfg_sign else "",
        "testemunha2_cpf": (getattr(cfg_sign, "testemunha2_cpf", None) or "").strip() if cfg_sign else "",
        "testemunha2_assinatura_b64": getattr(cfg_sign, "testemunha2_assinatura_b64", None) if cfg_sign else None,
    }


def localizar_servidor_do_contrato(db, models: Dict[str, Any], contrato):
    """Identifica o servidor vinculado ao contrato gerado no Gestoor360."""
    Funcionario = models["Funcionario"]
    if contrato.funcionario_id:
        f = db.session.get(Funcionario, contrato.funcionario_id)
        if f:
            return f
    if contrato.contratado_cpf:
        cpf_digits = re.sub(r"\D", "", contrato.contratado_cpf)
        if len(cpf_digits) == 11:
            f = Funcionario.query.filter(
                (Funcionario.cpf_limpo == cpf_digits) | (Funcionario.cpf == contrato.contratado_cpf)
            ).first()
            if f:
                return f
    return None


def obter_ou_criar_sessao_assinatura(
    db,
    models: Dict[str, Any],
    contrato,
    funcionario,
    user,
    secret_key: str,
    req_info: Dict[str, str],
):
    """
    Recupera uma sessão de assinatura em aberto para este contrato ou inicia uma nova.
    Retorna (assinatura, criada_agora).
    """
    AssinaturaContrato = models["AssinaturaContrato"]

    if contrato.status_assinatura == STATUS_CANCELADO:
        raise GestoorSignError("Este contrato foi cancelado e não pode ser assinado.", 400)
    if contrato.status_assinatura == STATUS_SUBSTITUIDO:
        raise GestoorSignError("Esta versão do contrato foi substituída por uma versão mais recente.", 400)

    # Se já assinado, retorna a assinatura oficial finalizada (somente leitura)
    assinada = (
        AssinaturaContrato.query.filter_by(
            contrato_id=contrato.id,
            status=SESSAO_ASSINADA,
        )
        .order_by(AssinaturaContrato.id.desc())
        .first()
    )
    if assinada:
        return assinada, False

    # Procura sessão ativa não cancelada/finalizada
    ativa = (
        AssinaturaContrato.query.filter(
            AssinaturaContrato.contrato_id == contrato.id,
            AssinaturaContrato.status.notin_([SESSAO_CANCELADA, SESSAO_ASSINADA]),
        )
        .order_by(AssinaturaContrato.id.desc())
        .first()
    )
    if ativa:
        return ativa, False

    tel_raw = (funcionario.telefone if funcionario else "") or ""
    cpf_raw = (funcionario.cpf if funcionario and funcionario.cpf else contrato.contratado_cpf) or ""
    cpf_digits = re.sub(r"\D", "", cpf_raw)
    ok_tel, _, tel_e164, _ = sms_service.normalizar_celular_br(tel_raw)

    tecnico_nome = (getattr(user, "nome_completo", None) or user.username or "Técnico RH").strip()
    fingerprint = hashlib.sha256(
        f"{user.id}|{req_info.get('ip', '')}|{req_info.get('ua', '')}|{secrets.token_hex(8)}".encode("utf-8")
    ).hexdigest()[:32]

    sessao = AssinaturaContrato(
        municipio_id=contrato.municipio_id,
        secretaria_id=contrato.secretaria_id,
        contrato_id=contrato.id,
        contrato_versao=int(getattr(contrato, "versao", 1) or 1),
        funcionario_id=funcionario.id if funcionario else contrato.funcionario_id,
        status=SESSAO_INICIADA,
        modalidade_juridica=MODALIDADE_SMS_CODIGO,
        servidor_nome=(funcionario.nome if funcionario else contrato.contratado_nome),
        servidor_cpf_mascarado=sms_service.mascarar_cpf(cpf_raw),
        servidor_cpf_hash=sha256_texto(cpf_digits, secret_key) if cpf_digits else None,
        telefone_mascarado=sms_service.mascarar_telefone(tel_raw) if tel_raw else "Não informado",
        telefone_e164_hash=sha256_texto(tel_e164, secret_key) if ok_tel else None,
        telefone_e164_enc=cifrar_dado_sensivel(tel_e164, secret_key) if ok_tel else None,
        tecnico_id=user.id,
        tecnico_nome=tecnico_nome,
        tecnico_username=user.username,
        termo_manifestacao_texto=TEXTO_MANIFESTACAO_VONTADE,
        ip_origem=(req_info.get("ip") or "")[:50] or None,
        user_agent=(req_info.get("ua") or "")[:250] or None,
        session_fingerprint=fingerprint,
        timezone_referencia="America/Sao_Paulo",
        criado_em=now_utc(),
    )
    db.session.add(sessao)
    db.session.flush()

    registrar_evento_assinatura(
        db,
        models,
        sessao,
        "INICIO_PROCEDIMENTO",
        f"Procedimento presencial Gestoor Sign iniciado pelo técnico {tecnico_nome} para o Contrato Nº {contrato.num_contrato} (v{sessao.contrato_versao}).",
        ator_tipo="TECNICO_RH",
        usuario_id=user.id,
        req_info=req_info,
        detalhes={"contrato_num": contrato.num_contrato, "versao": sessao.contrato_versao},
    )
    db.session.commit()
    return sessao, True


def confirmar_conferencia_presencial(
    db,
    models: Dict[str, Any],
    assinatura,
    contrato,
    funcionario,
    config,
    user,
    telefone_confirmado: str,
    presenca_confirmada: bool,
    dados_conferidos: bool,
    secret_key: str,
    timbre_path: Optional[str],
    req_info: Dict[str, str],
    format_data_extenso,
    format_rem_rs,
    local_assinatura: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Etapa 3: Confirma presença do servidor, celular válido, conferência do contrato integral,
    verifica conformidade municipal de modalidade mínima e congela o PDF base + SHA-256.
    """
    AssinaturaDocumentoArquivo = models["AssinaturaDocumentoArquivo"]

    if assinatura.status == SESSAO_ASSINADA:
        raise GestoorSignError("Este contrato já foi assinado eletronicamente.", 400)
    if assinatura.status == SESSAO_CANCELADA:
        raise GestoorSignError("Esta sessão de assinatura foi cancelada.", 400)

    permitido_sms, mod_exigida, msg_mod = verificar_modalidade_minima(config, contrato.tipo_contrato)
    if not permitido_sms:
        raise GestoorSignError(msg_mod, 403, {"modalidade_exigida": mod_exigida})

    if not presenca_confirmada or not dados_conferidos:
        raise GestoorSignError(
            "É obrigatório confirmar que o servidor está presente no RH, que os dados cadastrais estão corretos e que o contrato integral foi exibido para conferência.",
            400,
        )

    tel_usar = (telefone_confirmado or "").strip() or (funcionario.telefone if funcionario else "")
    ok_tel, digits_11, tel_e164, err_tel = sms_service.normalizar_celular_br(tel_usar)
    if not ok_tel:
        raise GestoorSignError(err_tel, 400)

    agora = now_utc()
    tel_formatado = f"({digits_11[:2]}) {digits_11[2:7]}-{digits_11[7:]}"

    # Atualiza e confirma o telefone no cadastro do servidor (Etapa 1 integrada)
    if funcionario:
        tel_anterior = (funcionario.telefone or "").strip()
        if re.sub(r"\D", "", tel_anterior) != digits_11:
            funcionario.telefone = tel_formatado
        funcionario.telefone_confirmado_em = agora
        funcionario.telefone_confirmado_por_id = user.id

    local_norm = normalizar_local_assinatura(local_assinatura or getattr(assinatura, "local_assinatura_json", None))
    assinatura.local_assinatura_json = json.dumps(local_norm, ensure_ascii=False)

    assinatura.telefone_mascarado = sms_service.mascarar_telefone(digits_11)
    assinatura.telefone_e164_hash = sha256_texto(tel_e164, secret_key)
    assinatura.telefone_e164_enc = cifrar_dado_sensivel(tel_e164, secret_key)
    assinatura.presenca_confirmada_em = agora
    assinatura.contrato_conferido_em = agora
    assinatura.tecnico_id = user.id
    assinatura.tecnico_nome = (getattr(user, "nome_completo", None) or user.username or "Técnico RH").strip()
    assinatura.tecnico_username = user.username

    # Congela PDF base da versão exata do contrato e gera SHA-256
    contrato_ctx = montar_contexto_contrato_pdf(contrato, db, models, format_data_extenso, format_rem_rs)
    pdf_base_bytes, pdf_base_sha256 = gestoor_sign_pdf.gerar_pdf_contrato_base(contrato_ctx, timbre_path=timbre_path)
    assinatura.hash_contrato_base_sha256 = pdf_base_sha256

    # Salva arquivo PDF base se ainda não existir com o mesmo hash nesta assinatura
    ja_existe_base = AssinaturaDocumentoArquivo.query.filter_by(
        assinatura_id=assinatura.id,
        tipo_arquivo="CONTRATO_BASE_PDF",
        sha256=pdf_base_sha256,
    ).first()
    if not ja_existe_base:
        num_slug = re.sub(r"[^A-Za-z0-9_-]", "_", contrato.num_contrato or str(contrato.id))
        arq = AssinaturaDocumentoArquivo(
            assinatura_id=assinatura.id,
            contrato_id=contrato.id,
            municipio_id=contrato.municipio_id,
            tipo_arquivo="CONTRATO_BASE_PDF",
            nome_arquivo=f"contrato_{num_slug}_v{assinatura.contrato_versao}_base.pdf",
            mime_type="application/pdf",
            tamanho_bytes=len(pdf_base_bytes),
            sha256=pdf_base_sha256,
            conteudo_b64=base64.b64encode(pdf_base_bytes).decode("ascii"),
            criado_em=agora,
        )
        db.session.add(arq)

    if assinatura.status in (SESSAO_INICIADA, SESSAO_FALHA):
        assinatura.status = SESSAO_CONFERIDA
    if contrato.status_assinatura == STATUS_AGUARDANDO:
        contrato.status_assinatura = STATUS_PENDENTE

    registrar_evento_assinatura(
        db,
        models,
        assinatura,
        "CONTRATO_CONFERIDO",
        f"Presença do servidor e telefone {assinatura.telefone_mascarado} confirmados; versão {assinatura.contrato_versao} congelada (SHA-256 {pdf_base_sha256[:16]}...).",
        ator_tipo="TECNICO_RH",
        usuario_id=user.id,
        req_info=req_info,
        detalhes={
            "telefone_mascarado": assinatura.telefone_mascarado,
            "hash_contrato_base_sha256": pdf_base_sha256,
            "local_assinatura": local_norm,
        },
    )
    db.session.commit()

    return {
        "assinatura_id": assinatura.id,
        "status": assinatura.status,
        "etapa": calcular_etapa_atual(assinatura),
        "telefone_mascarado": assinatura.telefone_mascarado,
        "hash_contrato_base_sha256": pdf_base_sha256,
        "local_assinatura": local_norm,
    }


def enviar_codigo_sms_sessao(
    db,
    models: Dict[str, Any],
    assinatura,
    contrato,
    config,
    user,
    secret_key: str,
    req_info: Dict[str, str],
) -> Dict[str, Any]:
    """
    Etapa 4 (Envio): Gera OTP de uso único (nunca salvo em texto puro), aplica cooldown/limites
    e dispara via Comtele (ou provedor configurado).
    """
    AssinaturaSmsOtp = models["AssinaturaSmsOtp"]
    Municipio = models["Municipio"]

    if assinatura.status == SESSAO_ASSINADA:
        raise GestoorSignError("Este contrato já foi assinado eletronicamente.", 400)
    if assinatura.status == SESSAO_CANCELADA:
        raise GestoorSignError("Esta sessão foi cancelada.", 400)
    if not assinatura.contrato_conferido_em or not assinatura.presenca_confirmada_em:
        raise GestoorSignError(
            "Confirme primeiro a presença do servidor e a conferência integral do contrato (Etapa 3) antes de enviar o SMS.",
            400,
        )

    agora = now_utc()

    # Verifica bloqueio por excesso de tentativas
    if assinatura.bloqueado_ate and assinatura.bloqueado_ate > agora:
        restante = int((assinatura.bloqueado_ate - agora).total_seconds())
        mins = max(1, (restante + 59) // 60)
        raise GestoorSignError(
            f"Autenticação temporariamente bloqueada por excesso de tentativas inválidas. Aguarde {mins} minuto(s).",
            423,
            {"bloqueado_segundos": restante},
        )

    permitido_sms, mod_exigida, msg_mod = verificar_modalidade_minima(config, contrato.tipo_contrato)
    if not permitido_sms:
        raise GestoorSignError(msg_mod, 403, {"modalidade_exigida": mod_exigida})

    tel_e164 = decifrar_dado_sensivel(assinatura.telefone_e164_enc or "", secret_key)
    if not tel_e164:
        raise GestoorSignError("Telefone confirmado não encontrado na sessão. Refaça a etapa de conferência.", 400)

    # Controle de reenvios e cooldown
    otps_anteriores = (
        AssinaturaSmsOtp.query.filter_by(assinatura_id=assinatura.id)
        .order_by(AssinaturaSmsOtp.enviado_em.desc())
        .all()
    )
    max_envios_total = int(config.otp_max_reenvios or 3) + 1  # 1 envio inicial + N reenvios
    if len(otps_anteriores) >= max_envios_total:
        assinatura.status = SESSAO_FALHA
        assinatura.bloqueado_ate = agora + timedelta(minutes=int(config.bloqueio_minutos or 30))
        contrato.status_assinatura = STATUS_FALHA_AUTH
        registrar_evento_assinatura(
            db,
            models,
            assinatura,
            "OTP_BLOQUEADO",
            f"Limite máximo de envios/reenvios de SMS ({max_envios_total}) atingido. Sessão bloqueada temporariamente.",
            ator_tipo="SISTEMA",
            usuario_id=user.id,
            req_info=req_info,
        )
        db.session.commit()
        raise GestoorSignError(
            f"Limite máximo de reenvios de SMS ({config.otp_max_reenvios}) excedido. Sessão bloqueada por {config.bloqueio_minutos} minutos.",
            429,
        )

    cooldown = int(config.otp_cooldown_reenvio_segundos or 60)
    if otps_anteriores:
        ultimo_envio = otps_anteriores[0].enviado_em
        decorrido = int((agora - ultimo_envio).total_seconds())
        if decorrido < cooldown:
            espera = cooldown - decorrido
            raise GestoorSignError(
                f"Aguarde {espera} segundo(s) antes de solicitar um novo código SMS.",
                429,
                {"cooldown_restante": espera},
            )

    # Invalida códigos anteriores não utilizados
    for otp_ant in otps_anteriores:
        if not otp_ant.usado and not otp_ant.invalidado:
            otp_ant.invalidado = True
            otp_ant.motivo_invalidacao = "SUBSTITUIDO_POR_REENVIO"

    tamanho_otp = int(config.otp_tamanho or 6)
    ttl_segundos = max(60, int(config.otp_expiracao_segundos or 300))
    max_tentativas = max(1, int(config.otp_max_tentativas or 3))

    codigo_plain = gerar_codigo_otp(tamanho_otp)
    salt = secrets.token_hex(16)
    codigo_hashed = hash_otp(codigo_plain, salt, secret_key)

    mun = db.session.get(Municipio, contrato.municipio_id) if contrato.municipio_id else None
    mun_nome = mun.nome if mun else "Prefeitura Municipal"

    # Dispara SMS pelo provedor configurado (Comtele Painel Novo V4 padrão em produção)
    comtele_key = obter_comtele_api_key(config, secret_key)
    try:
        sms_res = sms_service.enviar_sms_otp(
            telefone_raw=tel_e164,
            codigo_otp=codigo_plain,
            num_contrato=contrato.num_contrato,
            municipio_nome=mun_nome,
            provider_name=config.sms_provider,
            sender=config.sms_remetente or "GESTOOR360",
            expiracao_minutos=max(1, ttl_segundos // 60),
            comtele_api_key=comtele_key,
            comtele_panel_mode=getattr(config, "comtele_panel_mode", None) or "novo",
            comtele_route_id=getattr(config, "comtele_route_id", None) or 17,
        )
    except sms_service.SMSProviderError as exc:
        registrar_evento_assinatura(
            db,
            models,
            assinatura,
            "SMS_FALHA_ENVIO",
            f"Falha ao enviar SMS para {assinatura.telefone_mascarado}: {exc}",
            ator_tipo="SISTEMA",
            usuario_id=user.id,
            req_info=req_info,
        )
        db.session.commit()
        raise GestoorSignError(str(exc), 502)

    expira_em = agora + timedelta(seconds=ttl_segundos)
    otp_reg = AssinaturaSmsOtp(
        assinatura_id=assinatura.id,
        municipio_id=contrato.municipio_id,
        codigo_salt=salt,
        codigo_hash=codigo_hashed,
        telefone_mascarado=assinatura.telefone_mascarado,
        telefone_hash=assinatura.telefone_e164_hash,
        enviado_em=agora,
        expira_em=expira_em,
        tentativas_realizadas=0,
        max_tentativas=max_tentativas,
        usado=False,
        invalidado=False,
        provider_name=sms_res.provider,
        provider_message_id=sms_res.message_id,
        provider_status=sms_res.status,
        solicitado_por_id=user.id,
        ip_origem=(req_info.get("ip") or "")[:50] or None,
    )
    db.session.add(otp_reg)

    assinatura.status = SESSAO_SMS_ENVIADO
    assinatura.sms_enviado_em = agora
    assinatura.sms_provider_utilizado = sms_res.provider
    assinatura.sms_provider_message_id = sms_res.message_id
    contrato.status_assinatura = STATUS_PENDENTE

    eh_reenvio = len(otps_anteriores) > 0
    registrar_evento_assinatura(
        db,
        models,
        assinatura,
        "SMS_REENVIADO" if eh_reenvio else "SMS_ENVIADO",
        f"Código OTP de uso único enviado para {assinatura.telefone_mascarado} via {sms_res.provider.upper()} (Protocolo: {sms_res.message_id}). Expira em {ttl_segundos}s.",
        ator_tipo="TECNICO_RH",
        usuario_id=user.id,
        req_info=req_info,
        detalhes={
            "provider": sms_res.provider,
            "message_id": sms_res.message_id,
            "ttl_segundos": ttl_segundos,
            "reenvio": eh_reenvio,
        },
    )
    db.session.commit()

    resp = {
        "assinatura_id": assinatura.id,
        "status": assinatura.status,
        "etapa": calcular_etapa_atual(assinatura),
        "telefone_mascarado": assinatura.telefone_mascarado,
        "provider": sms_res.provider,
        "message_id": sms_res.message_id,
        "expira_em_segundos": ttl_segundos,
        "cooldown_segundos": cooldown,
        "tentativas_restantes": max_tentativas,
        "reenvios_restantes": max(0, max_envios_total - (len(otps_anteriores) + 1)),
        "enviado_em_brt": format_brt(agora),
    }
    # Apenas em modo homologacao_local (dev, bloqueado em produção)
    if sms_res.homologacao_codigo:
        resp["homologacao_codigo"] = sms_res.homologacao_codigo
    return resp


def validar_codigo_otp_sessao(
    db,
    models: Dict[str, Any],
    assinatura,
    contrato,
    config,
    codigo_digitado: str,
    user,
    secret_key: str,
    req_info: Dict[str, str],
) -> Dict[str, Any]:
    """
    Etapa 4 (Validação): Valida código OTP de uso único com proteção contra reutilização,
    expiração e bloqueio após tentativas excessivas.
    """
    AssinaturaSmsOtp = models["AssinaturaSmsOtp"]

    if assinatura.status == SESSAO_ASSINADA:
        raise GestoorSignError("Este contrato já foi assinado eletronicamente.", 400)
    if assinatura.status == SESSAO_CANCELADA:
        raise GestoorSignError("Esta sessão foi cancelada.", 400)
    if assinatura.status in (SESSAO_SMS_VALIDADO, SESSAO_CONCORDANCIA):
        return {
            "assinatura_id": assinatura.id,
            "status": assinatura.status,
            "etapa": calcular_etapa_atual(assinatura),
            "validado_em_brt": format_brt(assinatura.sms_validado_em),
            "termo_manifestacao": TEXTO_MANIFESTACAO_VONTADE,
        }

    agora = now_utc()
    if assinatura.bloqueado_ate and assinatura.bloqueado_ate > agora:
        restante = int((assinatura.bloqueado_ate - agora).total_seconds())
        mins = max(1, (restante + 59) // 60)
        raise GestoorSignError(
            f"Autenticação bloqueada por excesso de tentativas inválidas. Aguarde {mins} minuto(s).",
            423,
            {"bloqueado_segundos": restante},
        )

    codigo_limpo = re.sub(r"\D", "", str(codigo_digitado or ""))
    if not codigo_limpo:
        raise GestoorSignError("Informe o código numérico recebido por SMS pelo servidor.", 400)

    otp_ativo = (
        AssinaturaSmsOtp.query.filter_by(
            assinatura_id=assinatura.id,
            usado=False,
            invalidado=False,
        )
        .order_by(AssinaturaSmsOtp.enviado_em.desc())
        .first()
    )
    if not otp_ativo:
        raise GestoorSignError(
            "Nenhum código SMS ativo encontrado. Solicite o envio de um código para o celular do servidor.",
            400,
        )

    # Verifica expiração
    if otp_ativo.expira_em <= agora:
        otp_ativo.invalidado = True
        otp_ativo.motivo_invalidacao = "EXPIRADO"
        registrar_evento_assinatura(
            db,
            models,
            assinatura,
            "OTP_VALIDACAO_FALHA",
            "Tentativa de validação com código SMS expirado.",
            ator_tipo="TECNICO_RH",
            usuario_id=user.id,
            req_info=req_info,
            detalhes={"motivo": "EXPIRADO"},
        )
        db.session.commit()
        raise GestoorSignError("O código SMS expirou. Solicite o reenvio de um novo código.", 400)

    # Verifica limite de tentativas já atingido
    if (otp_ativo.tentativas_realizadas or 0) >= (otp_ativo.max_tentativas or 3):
        otp_ativo.invalidado = True
        otp_ativo.motivo_invalidacao = "EXCESSO_TENTATIVAS"
        assinatura.status = SESSAO_FALHA
        assinatura.bloqueado_ate = agora + timedelta(minutes=int(config.bloqueio_minutos or 30))
        contrato.status_assinatura = STATUS_FALHA_AUTH
        db.session.commit()
        raise GestoorSignError("Limite de tentativas excedido. Autenticação bloqueada.", 423)

    # Comparação em tempo constante (HMAC-SHA256)
    otp_ativo.tentativas_realizadas = (otp_ativo.tentativas_realizadas or 0) + 1
    correto = verificar_otp_hash(codigo_limpo, otp_ativo.codigo_salt, otp_ativo.codigo_hash, secret_key)

    if not correto:
        restantes = max(0, (otp_ativo.max_tentativas or 3) - otp_ativo.tentativas_realizadas)
        if restantes == 0:
            otp_ativo.invalidado = True
            otp_ativo.motivo_invalidacao = "EXCESSO_TENTATIVAS"
            assinatura.status = SESSAO_FALHA
            assinatura.bloqueado_ate = agora + timedelta(minutes=int(config.bloqueio_minutos or 30))
            contrato.status_assinatura = STATUS_FALHA_AUTH
            registrar_evento_assinatura(
                db,
                models,
                assinatura,
                "OTP_BLOQUEADO",
                f"Código SMS bloqueado após {otp_ativo.tentativas_realizadas} tentativas incorretas.",
                ator_tipo="SISTEMA",
                usuario_id=user.id,
                req_info=req_info,
                detalhes={"tentativas": otp_ativo.tentativas_realizadas},
            )
            db.session.commit()
            raise GestoorSignError(
                f"Código incorreto. Limite de tentativas atingido; autenticação bloqueada por {config.bloqueio_minutos} minuto(s).",
                423,
                {"tentativas_restantes": 0, "bloqueado": True},
            )

        registrar_evento_assinatura(
            db,
            models,
            assinatura,
            "OTP_VALIDACAO_FALHA",
            f"Código SMS incorreto informado (tentativa {otp_ativo.tentativas_realizadas} de {otp_ativo.max_tentativas}).",
            ator_tipo="TECNICO_RH",
            usuario_id=user.id,
            req_info=req_info,
            detalhes={"tentativa": otp_ativo.tentativas_realizadas, "restantes": restantes},
        )
        db.session.commit()
        raise GestoorSignError(
            f"Código SMS inválido. Restam {restantes} tentativa(s).",
            400,
            {"tentativas_restantes": restantes},
        )

    # Sucesso: marca código como usado (uso único garantido!)
    otp_ativo.usado = True
    otp_ativo.usado_em = agora
    assinatura.sms_validado_em = agora
    assinatura.status = SESSAO_SMS_VALIDADO

    registrar_evento_assinatura(
        db,
        models,
        assinatura,
        "OTP_VALIDADO",
        f"Código SMS de uso único validado com sucesso para o telefone {assinatura.telefone_mascarado}.",
        ator_tipo="SERVIDOR",
        usuario_id=user.id,
        req_info=req_info,
        detalhes={"otp_id": otp_ativo.id, "tentativas_usadas": otp_ativo.tentativas_realizadas},
    )
    db.session.commit()

    return {
        "assinatura_id": assinatura.id,
        "status": assinatura.status,
        "etapa": calcular_etapa_atual(assinatura),
        "validado_em_brt": format_brt(agora),
        "termo_manifestacao": TEXTO_MANIFESTACAO_VONTADE,
    }


def confirmar_vontade_e_finalizar(
    db,
    models: Dict[str, Any],
    assinatura,
    contrato,
    funcionario,
    config,
    user,
    declaracao_aceita: bool,
    cpf_ultimos4: str,
    confirmacao_servidor_nome: str,
    url_validador_base: str,
    timbre_path: Optional[str],
    req_info: Dict[str, str],
    format_data_extenso,
    format_rem_rs,
) -> Dict[str, Any]:
    """
    Etapas 5 e 6:
    - Exige validação prévia do OTP SMS (nunca finaliza sem OTP validado!).
    - Exige manifestação expressa de vontade diretamente pelo servidor (checkbox + 4 últimos dígitos do CPF).
    - Gera código único de validação + QR Code + PDF Final Assinado + Relatório de Evidências + SHA-256.
    - Atualiza ContratoGerado -> ASSINADO_ELETRONICAMENTE.
    - Arquiva automaticamente o PDF assinado no GED (DocumentoServidor -> CONTRATO_ASSINADO).
    """
    AssinaturaEvento = models["AssinaturaEvento"]
    AssinaturaDocumentoArquivo = models["AssinaturaDocumentoArquivo"]
    DocumentoServidor = models["DocumentoServidor"]

    if assinatura.status == SESSAO_ASSINADA:
        raise GestoorSignError("Este contrato já foi finalizado e assinado eletronicamente.", 400)
    if assinatura.status == SESSAO_CANCELADA:
        raise GestoorSignError("Esta sessão foi cancelada.", 400)
    if assinatura.status not in (SESSAO_SMS_VALIDADO, SESSAO_CONCORDANCIA) or not assinatura.sms_validado_em:
        raise GestoorSignError(
            "Não é permitido finalizar a assinatura sem validação prévia e bem-sucedida do código SMS.",
            400,
        )

    permitido_sms, mod_exigida, msg_mod = verificar_modalidade_minima(config, contrato.tipo_contrato)
    if not permitido_sms:
        raise GestoorSignError(msg_mod, 403, {"modalidade_exigida": mod_exigida})

    if not declaracao_aceita:
        raise GestoorSignError(
            "O servidor deve marcar expressamente a declaração de leitura e concordância com os termos do contrato.",
            400,
        )

    # Barreira de confirmação direta do servidor (4 últimos dígitos do CPF)
    cpf_contrato_digits = re.sub(
        r"\D",
        "",
        (funcionario.cpf if funcionario and funcionario.cpf else contrato.contratado_cpf) or "",
    )
    ult4_informado = re.sub(r"\D", "", str(cpf_ultimos4 or ""))
    if len(cpf_contrato_digits) == 11:
        if ult4_informado != cpf_contrato_digits[-4:]:
            raise GestoorSignError(
                "Os 4 últimos dígitos do CPF informados pelo servidor não conferem com o cadastro do contrato.",
                400,
            )

    agora = now_utc()
    assinatura.termo_manifestacao_texto = TEXTO_MANIFESTACAO_VONTADE
    assinatura.manifestacao_confirmada = True
    assinatura.manifestacao_confirmada_em = agora
    assinatura.metodo_confirmacao_servidor = "ACEITE_EXPRESSO_TELA_SERVIDOR_OTP_SMS_CPF4"
    assinatura.status = SESSAO_CONCORDANCIA

    registrar_evento_assinatura(
        db,
        models,
        assinatura,
        "MANIFESTACAO_CONFIRMADA",
        f"Servidor {assinatura.servidor_nome} confirmou expressamente a leitura e concordância integral com o contrato.",
        ator_tipo="SERVIDOR",
        usuario_id=None,  # Ação atribuída ao servidor, não ao técnico
        req_info=req_info,
        detalhes={
            "metodo": assinatura.metodo_confirmacao_servidor,
            "confirmacao_nome_informado": (confirmacao_servidor_nome or "").strip().upper()[:120],
            "tecnico_condutor_id": user.id,
        },
    )
    db.session.flush()

    # Gera código único de validação pública (garantindo unicidade)
    codigo_val = gerar_codigo_validacao(contrato.ano_exercicio)
    while models["AssinaturaContrato"].query.filter_by(codigo_validacao=codigo_val).first():
        codigo_val = gerar_codigo_validacao(contrato.ano_exercicio)

    assinatura.codigo_validacao = codigo_val
    assinatura.assinado_em = agora

    # Monta trilha de eventos atualizada para embutir no Relatório de Evidências
    eventos_db = (
        AssinaturaEvento.query.filter_by(assinatura_id=assinatura.id)
        .order_by(AssinaturaEvento.id.asc())
        .all()
    )
    eventos_lista = [
        {
            "tipo_evento": e.tipo_evento,
            "descricao": e.descricao,
            "ator_tipo": e.ator_tipo,
            "data_hora_brt": format_brt(e.data_hora),
            "hash_evento_atual": e.hash_evento_atual,
        }
        for e in eventos_db
    ]

    validar_url = f"{url_validador_base.rstrip('/')}?codigo={codigo_val}"
    contrato_ctx = montar_contexto_contrato_pdf(contrato, db, models, format_data_extenso, format_rem_rs)

    # Garante hash base do contrato caso ainda não exista
    if not assinatura.hash_contrato_base_sha256:
        _, base_sha = gestoor_sign_pdf.gerar_pdf_contrato_base(contrato_ctx, timbre_path=timbre_path)
        assinatura.hash_contrato_base_sha256 = base_sha

    pacote_evidencias_canonico = {
        "contrato_id": contrato.id,
        "num_contrato": contrato.num_contrato,
        "versao": assinatura.contrato_versao,
        "codigo_validacao": codigo_val,
        "modalidade_juridica": MODALIDADE_SMS_CODIGO,
        "servidor_nome": assinatura.servidor_nome,
        "servidor_cpf_mascarado": assinatura.servidor_cpf_mascarado,
        "telefone_mascarado": assinatura.telefone_mascarado,
        "tecnico_id": assinatura.tecnico_id,
        "tecnico_nome": assinatura.tecnico_nome,
        "data_geracao_utc": contrato.data_geracao.isoformat() if contrato.data_geracao else None,
        "conferido_utc": assinatura.contrato_conferido_em.isoformat() if assinatura.contrato_conferido_em else None,
        "sms_enviado_utc": assinatura.sms_enviado_em.isoformat() if assinatura.sms_enviado_em else None,
        "sms_validado_utc": assinatura.sms_validado_em.isoformat() if assinatura.sms_validado_em else None,
        "manifestacao_utc": assinatura.manifestacao_confirmada_em.isoformat(),
        "assinado_utc": assinatura.assinado_em.isoformat(),
        "termo_manifestacao_texto": assinatura.termo_manifestacao_texto,
        "hash_contrato_base_sha256": assinatura.hash_contrato_base_sha256,
        "sms_provider": assinatura.sms_provider_utilizado,
        "sms_message_id": assinatura.sms_provider_message_id,
        "ip_origem": assinatura.ip_origem,
        "session_fingerprint": assinatura.session_fingerprint,
    }
    hash_evidencias = hashlib.sha256(
        json.dumps(pacote_evidencias_canonico, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    assinatura.hash_evidencias_sha256 = hash_evidencias

    local_norm = normalizar_local_assinatura(getattr(assinatura, "local_assinatura_json", None))

    evidencia_ctx = {
        "codigo_validacao": codigo_val,
        "validar_url": validar_url,
        "status_label": "ASSINADO ELETRONICAMENTE",
        "local_assinatura": local_norm,
        "servidor_nome": assinatura.servidor_nome,
        "servidor_cpf_mascarado": assinatura.servidor_cpf_mascarado,
        "telefone_mascarado": assinatura.telefone_mascarado,
        "tecnico_nome": assinatura.tecnico_nome,
        "tecnico_username": assinatura.tecnico_username,
        "modalidade_label": MODALIDADE_SMS_LABEL,
        "ato_normativo": config.ato_normativo_referencia or "Lei nº 14.063/2020 • MP nº 2.200-2/2001 • LGPD",
        "data_geracao_brt": format_brt(contrato.data_geracao),
        "contrato_conferido_brt": format_brt(assinatura.contrato_conferido_em),
        "sms_enviado_brt": format_brt(assinatura.sms_enviado_em),
        "sms_validado_brt": format_brt(assinatura.sms_validado_em),
        "manifestacao_brt": format_brt(assinatura.manifestacao_confirmada_em),
        "assinado_em_brt": format_brt(assinatura.assinado_em),
        "sms_provider": assinatura.sms_provider_utilizado,
        "sms_message_id": assinatura.sms_provider_message_id,
        "termo_manifestacao_texto": assinatura.termo_manifestacao_texto,
        "metodo_confirmacao_servidor": assinatura.metodo_confirmacao_servidor,
        "hash_contrato_base_sha256": assinatura.hash_contrato_base_sha256,
        "hash_evidencias_sha256": hash_evidencias,
        "ip_origem": assinatura.ip_origem,
        "user_agent": assinatura.user_agent,
        "session_fingerprint": assinatura.session_fingerprint,
        "eventos": eventos_lista,
    }

    # Gera os 2 PDFs oficiais selados no servidor
    pdf_final_bytes, pdf_final_sha256 = gestoor_sign_pdf.gerar_pdf_contrato_assinado(
        contrato_ctx, evidencia_ctx, timbre_path=timbre_path
    )
    pdf_evid_bytes, pdf_evid_sha256 = gestoor_sign_pdf.gerar_pdf_relatorio_evidencias(
        contrato_ctx, evidencia_ctx
    )

    assinatura.hash_documento_final_sha256 = pdf_final_sha256
    assinatura.status = SESSAO_ASSINADA

    num_slug = re.sub(r"[^A-Za-z0-9_-]", "_", contrato.num_contrato or str(contrato.id))
    nome_pdf_final = f"contrato_{num_slug}_v{assinatura.contrato_versao}_assinado_gestoorsign.pdf"
    nome_pdf_evid = f"evidencias_{num_slug}_v{assinatura.contrato_versao}_gestoorsign.pdf"

    pdf_final_b64 = base64.b64encode(pdf_final_bytes).decode("ascii")
    pdf_evid_b64 = base64.b64encode(pdf_evid_bytes).decode("ascii")

    db.session.add(
        AssinaturaDocumentoArquivo(
            assinatura_id=assinatura.id,
            contrato_id=contrato.id,
            municipio_id=contrato.municipio_id,
            tipo_arquivo="CONTRATO_ASSINADO_PDF",
            nome_arquivo=nome_pdf_final,
            mime_type="application/pdf",
            tamanho_bytes=len(pdf_final_bytes),
            sha256=pdf_final_sha256,
            conteudo_b64=pdf_final_b64,
            criado_em=agora,
        )
    )
    db.session.add(
        AssinaturaDocumentoArquivo(
            assinatura_id=assinatura.id,
            contrato_id=contrato.id,
            municipio_id=contrato.municipio_id,
            tipo_arquivo="RELATORIO_EVIDENCIAS_PDF",
            nome_arquivo=nome_pdf_evid,
            mime_type="application/pdf",
            tamanho_bytes=len(pdf_evid_bytes),
            sha256=pdf_evid_sha256,
            conteudo_b64=pdf_evid_b64,
            criado_em=agora,
        )
    )

    # Atualiza status oficial do ContratoGerado
    contrato.status_assinatura = STATUS_ASSINADO
    contrato.modalidade_assinatura = MODALIDADE_SMS_CODIGO
    contrato.data_assinatura_eletronica = agora
    contrato.codigo_validacao = codigo_val
    contrato.hash_documento_sha256 = pdf_final_sha256

    # Arquivamento automático no GED (Decisão #3 aprovada pelo usuário)
    ged_doc_id = None
    if funcionario and (config.arquivar_ged_automatico is not False):
        doc_ged = DocumentoServidor(
            funcionario_id=funcionario.id,
            secretaria_id=contrato.secretaria_id or funcionario.secretaria_id,
            tipo_documento="CONTRATO_ASSINADO",
            nome_arquivo=nome_pdf_final[:195],
            mime_type="application/pdf",
            tamanho_bytes=len(pdf_final_bytes),
            sha256=pdf_final_sha256,
            conteudo_b64=pdf_final_b64,
            observacao=f"Arquivado automaticamente via Gestoor Sign • Contrato Nº {contrato.num_contrato} (v{assinatura.contrato_versao}) • Código {codigo_val}"[:250],
            validado=True,
            validado_por_id=user.id,
            validado_em=agora,
            enviado_por_id=user.id,
            data_upload=agora,
        )
        db.session.add(doc_ged)
        db.session.flush()
        ged_doc_id = doc_ged.id

    registrar_evento_assinatura(
        db,
        models,
        assinatura,
        "DOCUMENTO_SELADO",
        f"Contrato Nº {contrato.num_contrato} (v{assinatura.contrato_versao}) assinado eletronicamente. Código {codigo_val} • SHA-256 {pdf_final_sha256[:16]}...",
        ator_tipo="SISTEMA",
        usuario_id=user.id,
        req_info=req_info,
        detalhes={
            "codigo_validacao": codigo_val,
            "hash_documento_final_sha256": pdf_final_sha256,
            "hash_evidencias_sha256": hash_evidencias,
            "ged_documento_id": ged_doc_id,
        },
    )
    db.session.commit()

    return {
        "assinatura_id": assinatura.id,
        "status": STATUS_ASSINADO,
        "etapa": 6,
        "codigo_validacao": codigo_val,
        "validar_url": validar_url,
        "hash_documento_final_sha256": pdf_final_sha256,
        "hash_contrato_base_sha256": assinatura.hash_contrato_base_sha256,
        "assinado_em_brt": format_brt(agora),
        "ged_arquivado": bool(ged_doc_id),
        "ged_documento_id": ged_doc_id,
        "qrcode_data_uri": gestoor_sign_pdf.gerar_qrcode_data_uri(validar_url),
    }


def cancelar_processo_assinatura(
    db,
    models: Dict[str, Any],
    contrato,
    assinatura,
    user,
    motivo: str,
    req_info: Dict[str, str],
) -> Dict[str, Any]:
    """Cancelamento lógico auditado (nunca destrói evidências nem exclui contrato assinado)."""
    motivo_limpo = (motivo or "").strip()
    if len(motivo_limpo) < 5:
        raise GestoorSignError("Informe o motivo do cancelamento (mínimo 5 caracteres).", 400)
    if contrato.status_assinatura == STATUS_ASSINADO or (assinatura and assinatura.status == SESSAO_ASSINADA):
        raise GestoorSignError(
            "Contratos já assinados eletronicamente são imutáveis e não podem ser cancelados por esta ação. Para retificar conteúdo, gere uma Nova Versão.",
            400,
        )

    agora = now_utc()
    contrato.status_assinatura = STATUS_CANCELADO
    contrato.cancelado_em = agora
    contrato.cancelado_por_id = user.id
    contrato.motivo_cancelamento = motivo_limpo

    if assinatura:
        assinatura.status = SESSAO_CANCELADA
        for otp in assinatura.otps:
            if not otp.usado and not otp.invalidado:
                otp.invalidado = True
                otp.motivo_invalidacao = "SESSAO_CANCELADA"
        registrar_evento_assinatura(
            db,
            models,
            assinatura,
            "CANCELAMENTO",
            f"Processo cancelado por {user.username}. Motivo: {motivo_limpo}",
            ator_tipo="TECNICO_RH",
            usuario_id=user.id,
            req_info=req_info,
            detalhes={"motivo": motivo_limpo},
        )
    db.session.commit()
    return {"contrato_id": contrato.id, "status": STATUS_CANCELADO}


def gerar_nova_versao_contrato(
    db,
    models: Dict[str, Any],
    contrato_anterior,
    user,
    motivo: str,
    req_info: Dict[str, str],
    overrides: Optional[Dict[str, Any]] = None,
):
    """
    Qualquer alteração posterior em um contrato assinado gera uma nova versão (v+1),
    preservando integralmente a versão anterior (status SUBSTITUIDO) e exigindo
    novo procedimento completo de assinatura no Gestoor Sign.
    """
    ContratoGerado = models["ContratoGerado"]
    AssinaturaContrato = models["AssinaturaContrato"]

    motivo_limpo = (motivo or "").strip()
    if len(motivo_limpo) < 5:
        raise GestoorSignError("Informe o motivo da retificação / nova versão (mínimo 5 caracteres).", 400)

    if contrato_anterior.status_assinatura == STATUS_SUBSTITUIDO:
        raise GestoorSignError("Esta versão já foi substituída. Utilize a versão mais recente do contrato.", 400)

    overrides = overrides or {}
    nova_versao_num = int(getattr(contrato_anterior, "versao", 1) or 1) + 1
    origem_id = contrato_anterior.contrato_origem_id or contrato_anterior.id

    novo = ContratoGerado(
        municipio_id=contrato_anterior.municipio_id,
        secretaria_id=contrato_anterior.secretaria_id,
        num_contrato=contrato_anterior.num_contrato,
        ano_exercicio=contrato_anterior.ano_exercicio,
        funcionario_id=contrato_anterior.funcionario_id,
        versao=nova_versao_num,
        contrato_origem_id=origem_id,
        versao_anterior_id=contrato_anterior.id,
        tipo_contrato=overrides.get("tipo_contrato", contrato_anterior.tipo_contrato or "TEMPORARIO"),
        status_assinatura=STATUS_AGUARDANDO,
        contratado_nome=overrides.get("contratado_nome", contrato_anterior.contratado_nome),
        contratado_cpf=overrides.get("contratado_cpf", contrato_anterior.contratado_cpf),
        contratado_rg=overrides.get("contratado_rg", contrato_anterior.contratado_rg),
        contratado_nacionalidade=overrides.get("contratado_nacionalidade", contrato_anterior.contratado_nacionalidade),
        contratado_naturalidade=overrides.get("contratado_naturalidade", contrato_anterior.contratado_naturalidade),
        contratado_estado_civil=overrides.get("contratado_estado_civil", contrato_anterior.contratado_estado_civil),
        contratado_endereco=overrides.get("contratado_endereco", contrato_anterior.contratado_endereco),
        contratado_cidade=overrides.get("contratado_cidade", contrato_anterior.contratado_cidade),
        funcao_nome=overrides.get("funcao_nome", contrato_anterior.funcao_nome),
        remuneracao=overrides.get("remuneracao", contrato_anterior.remuneracao),
        remuneracao_extenso=overrides.get("remuneracao_extenso", contrato_anterior.remuneracao_extenso),
        jornada_trabalho=overrides.get("jornada_trabalho", contrato_anterior.jornada_trabalho),
        dt_inicio=overrides.get("dt_inicio", contrato_anterior.dt_inicio),
        dt_termino=overrides.get("dt_termino", contrato_anterior.dt_termino),
        dt_assinatura=overrides.get("dt_assinatura", contrato_anterior.dt_assinatura),
        representante_nome=overrides.get("representante_nome", contrato_anterior.representante_nome),
        representante_cargo=overrides.get("representante_cargo", contrato_anterior.representante_cargo),
        representante_rg_cpf=overrides.get("representante_rg_cpf", contrato_anterior.representante_rg_cpf),
        representante_endereco=overrides.get("representante_endereco", contrato_anterior.representante_endereco),
        data_geracao=now_utc(),
        quem_gerou_id=user.id,
        editado=True,
        motivo_edicao=f"[Nova Versão v{nova_versao_num}] {motivo_limpo}",
        data_edicao=now_utc(),
        quem_editou_id=user.id,
    )
    contrato_anterior.status_assinatura = STATUS_SUBSTITUIDO
    db.session.add(novo)
    db.session.flush()

    ass_ant = (
        AssinaturaContrato.query.filter_by(contrato_id=contrato_anterior.id)
        .order_by(AssinaturaContrato.id.desc())
        .first()
    )
    if ass_ant:
        registrar_evento_assinatura(
            db,
            models,
            ass_ant,
            "NOVA_VERSAO_GERADA",
            f"Versão v{nova_versao_num} (contrato_id={novo.id}) gerada por {user.username}. Motivo: {motivo_limpo}. Novo procedimento de assinatura exigido.",
            ator_tipo="TECNICO_RH",
            usuario_id=user.id,
            req_info=req_info,
            detalhes={"novo_contrato_id": novo.id, "nova_versao": nova_versao_num, "motivo": motivo_limpo},
        )

    db.session.commit()
    return novo
