"""
Módulo de Serviço — SERVIDOR 360 (App do Servidor Municipal em PWA)
===================================================================
Responsável pelas regras de negócio, segurança, biometria facial de 1º acesso,
solicitações de alteração cadastral com whitelist segura, QR Code da carteira
funcional digital e geração dos ícones oficiais do PWA.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
import unicodedata
import uuid
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

import pytz
import qrcode
from PIL import Image, ImageDraw, ImageFont

APP_NAME = "SERVIDOR 360"
APP_SHORT_NAME = "SERVIDOR 360"
APP_FULL_NAME = "SERVIDOR 360 — App do Servidor Municipal"
APP_THEME_COLOR = "#0B3D2E"
APP_BG_COLOR = "#0B3D2E"
APP_ACCENT_YELLOW = "#FACC15"
APP_ACCENT_GREEN = "#10B981"

# Limiar de comparação facial 1:1 (distância euclidiana do @vladmandic/face-api)
# Quanto menor a distância, maior a semelhança. 0.54 é equilibrado para 1:1 em câmeras móveis.
FACIAL_MAX_DISTANCE = 0.54
ONBOARDING_TTL_SECONDS = 900  # 15 minutos
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

MAX_ANEXO_BYTES = 3 * 1024 * 1024  # 3 MB
ALLOWED_ANEXO_EXTS = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
}

# Categorias e whitelist rigorosa de campos que o servidor pode solicitar alteração.
# Campos estratégicos/financeiros (cargo, lotação, salário, vínculo, validação, indicações)
# NUNCA podem ser alterados automaticamente pelo servidor.
CATEGORIAS_ALTERACAO: Dict[str, Dict[str, Any]] = {
    "CONTATO": {
        "label": "Contato e Emergência",
        "icon": "ph-phone",
        "desc": "Telefone, WhatsApp, e-mail e contato de emergência",
        "campos": [
            {"name": "telefone", "label": "Telefone / WhatsApp", "type": "tel", "max": 20, "placeholder": "(89) 99999-9999"},
            {"name": "email", "label": "E-mail", "type": "email", "max": 100, "placeholder": "servidor@email.com"},
            {"name": "contato_emergencia_nome", "label": "Nome (Contato de Emergência)", "type": "text", "max": 150, "placeholder": "Nome de um familiar ou responsável"},
            {"name": "contato_emergencia_tel", "label": "Telefone de Emergência", "type": "tel", "max": 20, "placeholder": "(89) 99999-9999"},
        ],
    },
    "ENDERECO": {
        "label": "Endereço Residencial",
        "icon": "ph-map-pin",
        "desc": "CEP, rua/número, bairro, cidade, zona e comunidade",
        "campos": [
            {"name": "cep", "label": "CEP", "type": "text", "max": 10, "placeholder": "64300-000"},
            {"name": "endereco", "label": "Logradouro e Número", "type": "text", "max": 200, "placeholder": "Rua, nº, complemento"},
            {"name": "bairro", "label": "Bairro", "type": "text", "max": 100, "placeholder": "Nome do bairro"},
            {"name": "cidade", "label": "Cidade", "type": "text", "max": 100, "placeholder": "Cidade"},
            {"name": "uf", "label": "UF", "type": "text", "max": 2, "placeholder": "PI"},
            {"name": "zona_moradia", "label": "Zona de Moradia", "type": "select", "options": ["URBANA", "RURAL"]},
            {"name": "povoado_comunidade", "label": "Povoado / Comunidade", "type": "text", "max": 120, "placeholder": "Se zona rural"},
        ],
    },
    "PESSOAL": {
        "label": "Dados Pessoais e Documentos",
        "icon": "ph-identification-card",
        "desc": "Estado civil, escolaridade, RG, PIS/PASEP, CNH, dependentes",
        "campos": [
            {"name": "estado_civil", "label": "Estado Civil", "type": "select", "options": ["SOLTEIRO(A)", "CASADO(A)", "DIVORCIADO(A)", "VIÚVO(A)", "UNIÃO ESTÁVEL"]},
            {"name": "escolaridade", "label": "Escolaridade", "type": "select", "options": ["FUNDAMENTAL INCOMPLETO", "FUNDAMENTAL COMPLETO", "MÉDIO INCOMPLETO", "MÉDIO COMPLETO", "TÉCNICO", "SUPERIOR INCOMPLETO", "SUPERIOR COMPLETO", "PÓS-GRADUAÇÃO / ESPECIALIZAÇÃO", "MESTRADO", "DOUTORADO"]},
            {"name": "especialidade", "label": "Formação / Especialidade", "type": "text", "max": 150, "placeholder": "Ex.: Pedagogia, Enfermagem..."},
            {"name": "rg", "label": "Número do RG", "type": "text", "max": 20, "placeholder": "Número do RG"},
            {"name": "orgao_emissor_rg", "label": "Órgão Emissor RG", "type": "text", "max": 20, "placeholder": "Ex.: SSP/PI"},
            {"name": "pis", "label": "PIS / PASEP", "type": "text", "max": 20, "placeholder": "Número PIS/PASEP"},
            {"name": "titulo_eleitor", "label": "Título de Eleitor", "type": "text", "max": 20, "placeholder": "Número do título"},
            {"name": "ctps", "label": "CTPS", "type": "text", "max": 50, "placeholder": "Número / Série CTPS"},
            {"name": "cnh", "label": "CNH", "type": "text", "max": 20, "placeholder": "Número CNH"},
            {"name": "tipo_sanguineo", "label": "Tipo Sanguíneo", "type": "select", "options": ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]},
            {"name": "qtd_dependentes", "label": "Quantidade de Dependentes", "type": "number", "max": 2, "placeholder": "0"},
        ],
    },
    "BANCARIO": {
        "label": "Dados Bancários",
        "icon": "ph-bank",
        "desc": "Banco, agência, número da conta e tipo de conta",
        "campos": [
            {"name": "banco", "label": "Banco", "type": "text", "max": 50, "placeholder": "Ex.: Banco do Brasil, Caixa..."},
            {"name": "agencia", "label": "Agência", "type": "text", "max": 20, "placeholder": "Ex.: 0123-4"},
            {"name": "conta", "label": "Número da Conta", "type": "text", "max": 20, "placeholder": "Ex.: 12345-6"},
            {"name": "tipo_conta", "label": "Tipo de Conta", "type": "select", "options": ["CORRENTE", "POUPANÇA", "SALÁRIO"]},
        ],
    },
    "OUTROS": {
        "label": "Outras Correções (Análise RH)",
        "icon": "ph-chat-teardrop-text",
        "desc": "Relate qualquer divergência cadastral ou funcional para o RH verificar",
        "campos": [],
    },
}

FIELD_LABELS: Dict[str, str] = {}
FIELD_META: Dict[str, Dict[str, Any]] = {}
for _cat_key, _cat_info in CATEGORIAS_ALTERACAO.items():
    for _c in _cat_info["campos"]:
        FIELD_LABELS[_c["name"]] = _c["label"]
        FIELD_META[_c["name"]] = _c


def now_br() -> datetime:
    return datetime.now(pytz.timezone("America/Sao_Paulo"))


def saudacao_horario() -> str:
    hora = now_br().hour
    if hora < 12:
        return "Bom dia"
    if hora < 18:
        return "Boa tarde"
    return "Boa noite"


def normalizar_cpf(cpf: Optional[str]) -> str:
    return re.sub(r"\D", "", str(cpf or ""))[:11]


def formatar_cpf(cpf: Optional[str]) -> str:
    d = normalizar_cpf(cpf)
    if len(d) != 11:
        return str(cpf or "")
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"


def mascarar_cpf(cpf: Optional[str]) -> str:
    d = normalizar_cpf(cpf)
    if len(d) != 11:
        return "***"
    return f"***.{d[3:6]}.{d[6:9]}-**"


def mascarar_valor_sensivel(valor: Optional[str], visiveis_fim: int = 3) -> str:
    s = str(valor or "").strip()
    if not s:
        return "—"
    if len(s) <= visiveis_fim:
        return "*" * len(s)
    return ("•" * max(4, len(s) - visiveis_fim)) + s[-visiveis_fim:]


def normalizar_texto_comparacao(texto: Optional[str]) -> str:
    if not texto:
        return ""
    s = unicodedata.normalize("NFKD", str(texto).strip().upper())
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^A-Z0-9\s]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def extrair_foto_referencia(funcionario: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Retorna (data_uri, fonte) priorizando a foto tirada no cadastro do RH (foto_3x4_b64),
    com fallback para foto_biometria. Se nenhuma existir, retorna (None, None).
    """
    if not funcionario:
        return None, None

    candidatos = [
        ("foto_3x4", getattr(funcionario, "foto_3x4_b64", None)),
        ("foto_biometria", getattr(funcionario, "foto_biometria", None)),
    ]
    for fonte, raw in candidatos:
        if raw and isinstance(raw, str) and len(raw.strip()) > 80:
            val = raw.strip()
            if val.startswith("data:image/"):
                return val, fonte
            return f"data:image/jpeg;base64,{val}", fonte
    return None, None


def verificar_elegibilidade_servidor(funcionario: Any) -> Tuple[bool, str, str]:
    """
    Regra oficial do SERVIDOR 360:
    1. Servidor deve existir e estar ATIVO.
    2. Cadastro deve estar VALIDADO pelo RH.
    3. Deve possuir foto cadastrada no RH (foto_3x4_b64 ou foto_biometria) — caso contrário, BLOQUEIA.
    """
    if not funcionario:
        return (
            False,
            "NAO_ENCONTRADO",
            "Não localizamos um cadastro ativo com os dados informados. Verifique o CPF e tente novamente.",
        )

    if getattr(funcionario, "ativo", True) is False:
        return (
            False,
            "INATIVO",
            "Seu vínculo consta como inativo no sistema municipal. Em caso de dúvida, procure o RH da sua secretaria.",
        )

    if not getattr(funcionario, "validado", False):
        return (
            False,
            "NAO_VALIDADO",
            "Seu cadastro ainda está aguardando validação oficial do RH. Assim que validado, seu acesso ao SERVIDOR 360 será liberado.",
        )

    foto_uri, _ = extrair_foto_referencia(funcionario)
    if not foto_uri:
        return (
            False,
            "SEM_FOTO",
            "Seu cadastro ainda não possui foto registrada no RH. Por segurança, o primeiro acesso exige reconhecimento facial. Procure o setor de RH da sua secretaria para cadastrar sua foto 3x4 e liberar o aplicativo.",
        )

    return True, "OK", "Elegível"


def conferir_dados_primeiro_acesso(
    funcionario: Any,
    data_nasc_str: str,
    confirmacao_extra: str = "",
) -> Tuple[bool, str]:
    """
    Valida os dados pessoais informados na Etapa 1 do Primeiro Acesso:
    - Data de nascimento obrigatória (compara com funcionario.data_nasc).
    - Confirmação adicional: primeiro nome da mãe OU 4 últimos dígitos do telefone
      (quando esses dados existirem no cadastro do RH).
    """
    if not funcionario:
        return False, "Servidor não encontrado."

    if not data_nasc_str:
        return False, "Informe sua data de nascimento."

    try:
        dt_informada = datetime.strptime(data_nasc_str.strip(), "%Y-%m-%d").date()
    except ValueError:
        try:
            dt_informada = datetime.strptime(data_nasc_str.strip(), "%d/%m/%Y").date()
        except ValueError:
            return False, "Data de nascimento em formato inválido."

    if not funcionario.data_nasc or funcionario.data_nasc != dt_informada:
        return False, "Os dados informados não conferem com o cadastro do RH. Verifique o CPF e a data de nascimento."

    # Validação secundária (primeiro nome da mãe OU 4 últimos dígitos do celular)
    mae_norm = normalizar_texto_comparacao(getattr(funcionario, "mae", None))
    primeiro_nome_mae = mae_norm.split(" ")[0] if mae_norm else ""
    tel_digitos = re.sub(r"\D", "", str(getattr(funcionario, "telefone", "") or ""))
    ultimos4_tel = tel_digitos[-4:] if len(tel_digitos) >= 4 else ""

    if primeiro_nome_mae or ultimos4_tel:
        extra_raw = (confirmacao_extra or "").strip()
        if not extra_raw:
            return False, "Informe a confirmação adicional (primeiro nome da sua mãe ou os 4 últimos dígitos do celular cadastrado)."
        extra_norm = normalizar_texto_comparacao(extra_raw).split(" ")[0] if normalizar_texto_comparacao(extra_raw) else ""
        extra_digitos = re.sub(r"\D", "", extra_raw)

        ok_mae = bool(primeiro_nome_mae and extra_norm == primeiro_nome_mae)
        ok_tel = bool(ultimos4_tel and len(extra_digitos) >= 4 and extra_digitos[-4:] == ultimos4_tel)
        if not (ok_mae or ok_tel):
            return (
                False,
                "A confirmação adicional não confere com o registro do RH (digite o primeiro nome da mãe ou os 4 últimos dígitos do celular cadastrado).",
            )

    return True, "OK"


def calcular_score_similaridade(distancia: float) -> float:
    """Converte distância euclidiana (0.0 a ~1.0) em percentual amigável de similaridade (0 a 100%)."""
    try:
        d = max(0.0, min(1.0, float(distancia)))
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, (1.0 - d) * 100.0), 1)


def validar_selfie_b64(selfie_b64: Optional[str]) -> Optional[str]:
    """Sanitiza e valida tamanho da selfie de auditoria enviada em Base64 (máx. 600 KB)."""
    if not selfie_b64 or not isinstance(selfie_b64, str):
        return None
    s = selfie_b64.strip()
    if len(s) > 850_000:
        return None
    if s.startswith("data:image/"):
        return s
    return f"data:image/jpeg;base64,{s}"


def gerar_protocolo_alteracao() -> str:
    ano = now_br().year
    sufixo = uuid.uuid4().hex[:6].upper()
    return f"ALT-{ano}-{sufixo}"


def validar_anexo_solicitacao(file_storage: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Valida anexo opcional enviado pelo servidor e retorna (nome, mime, b64)."""
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None, None, None

    nome_orig = os.path.basename(file_storage.filename.strip())
    ext = nome_orig.rsplit(".", 1)[-1].lower() if "." in nome_orig else ""
    if ext not in ALLOWED_ANEXO_EXTS:
        raise ValueError("Formato de anexo não permitido. Envie apenas PDF, JPG, PNG ou WEBP.")

    raw = file_storage.read()
    if not raw:
        return None, None, None
    if len(raw) > MAX_ANEXO_BYTES:
        raise ValueError("O anexo ultrapassa o limite máximo de 3 MB.")

    mime = ALLOWED_ANEXO_EXTS[ext]
    b64 = base64.b64encode(raw).decode("utf-8")
    return nome_orig[:180], mime, b64


def preparar_dados_solicitacao(
    funcionario: Any,
    categoria: str,
    form_data: Any,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Extrai exclusivamente campos permitidos pela whitelist da categoria selecionada
    que efetivamente diferem do valor atual na ficha do servidor.
    """
    cat = (categoria or "").strip().upper()
    if cat not in CATEGORIAS_ALTERACAO:
        raise ValueError("Categoria de alteração inválida.")

    dados_anteriores: Dict[str, Any] = {}
    dados_solicitados: Dict[str, Any] = {}

    for campo in CATEGORIAS_ALTERACAO[cat]["campos"]:
        fname = campo["name"]
        novo_raw = (form_data.get(f"campo_{fname}") or "").strip()
        if novo_raw == "":
            continue

        if campo["type"] == "number":
            try:
                novo_val: Any = max(0, min(99, int(re.sub(r"\D", "", novo_raw) or "0")))
            except ValueError:
                continue
        else:
            max_len = int(campo.get("max") or 150)
            novo_val = novo_raw[:max_len]
            if fname == "uf":
                novo_val = novo_val.upper()

        atual_raw = getattr(funcionario, fname, None)
        atual_cmp = "" if atual_raw is None else str(atual_raw).strip()
        novo_cmp = str(novo_val).strip()

        if atual_cmp != novo_cmp:
            dados_anteriores[fname] = atual_raw
            dados_solicitados[fname] = novo_val

    return dados_anteriores, dados_solicitados


def aplicar_alteracao_no_funcionario(
    funcionario: Any,
    dados_solicitados: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Aplica com segurança os campos aprovados pelo RH na instância Funcionario.
    Retorna (valores_antes, valores_depois) para auditoria forense.
    """
    antes: Dict[str, Any] = {}
    depois: Dict[str, Any] = {}

    for fname, novo_val in (dados_solicitados or {}).items():
        if fname not in FIELD_META:
            continue
        if not hasattr(funcionario, fname):
            continue

        meta = FIELD_META[fname]
        atual_val = getattr(funcionario, fname, None)
        antes[fname] = atual_val

        if meta["type"] == "number":
            try:
                val_final: Any = max(0, min(99, int(novo_val)))
            except (TypeError, ValueError):
                continue
        else:
            max_len = int(meta.get("max") or 150)
            val_final = str(novo_val).strip()[:max_len]
            if fname == "uf":
                val_final = val_final.upper()

        setattr(funcionario, fname, val_final)
        depois[fname] = val_final

    return antes, depois


def formatar_diff_solicitacao(dados_anteriores_json: Optional[str], dados_solicitados_json: Optional[str]) -> List[Dict[str, Any]]:
    """Transforma JSONs de solicitação em lista amigável para renderização nos templates."""
    try:
        antes = json.loads(dados_anteriores_json or "{}") or {}
    except Exception:
        antes = {}
    try:
        solicitados = json.loads(dados_solicitados_json or "{}") or {}
    except Exception:
        solicitados = {}

    itens = []
    for fname, novo in solicitados.items():
        itens.append({
            "campo": fname,
            "label": FIELD_LABELS.get(fname, fname.replace("_", " ").title()),
            "antes": antes.get(fname) if antes.get(fname) not in (None, "") else "—",
            "depois": novo if novo not in (None, "") else "—",
        })
    return itens


def gerar_qr_code_data_uri(conteudo: str) -> str:
    """Gera QR Code PNG compacto como data URI para a Carteira Funcional Digital."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(conteudo)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0B3D2E", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64}"


def _desenhar_icone_pwa(tamanho: int, maskable: bool = False) -> Image.Image:
    """
    Desenha o ícone oficial do PWA SERVIDOR 360 na paleta Gestoor360:
    fundo verde-escuro institucional (#0B3D2E), aro/acento amarelo (#FACC15) e emblema 360 limpo.
    """
    img = Image.new("RGBA", (tamanho, tamanho), (11, 61, 46, 255))
    draw = ImageDraw.Draw(img)

    # Gradiente sutil vertical no fundo verde
    for y in range(tamanho):
        ratio = y / max(1, tamanho - 1)
        r = int(11 + (20 - 11) * ratio)
        g = int(61 + (83 - 61) * ratio)
        b = int(46 + (45 - 46) * ratio)
        draw.line([(0, y), (tamanho, y)], fill=(r, g, b, 255))

    # Detalhe geométrico curvo superior (ecoando o design do app)
    draw.ellipse(
        [-int(tamanho * 0.25), -int(tamanho * 0.45), int(tamanho * 1.15), int(tamanho * 0.55)],
        fill=(16, 185, 129, 32),
    )

    pad = int(tamanho * (0.18 if maskable else 0.11))
    # Moldura arredondada interna / emblema central
    cx, cy = tamanho // 2, tamanho // 2
    raio = (tamanho - pad * 2) // 2

    # Círculo externo amarelo suave
    espessura = max(4, tamanho // 34)
    draw.ellipse(
        [cx - raio, cy - raio, cx + raio, cy + raio],
        outline=(250, 204, 21, 255),
        width=espessura,
    )

    # Círculo interno verde vivo sutil
    r_in = int(raio * 0.84)
    draw.ellipse(
        [cx - r_in, cy - r_in, cx + r_in, cy + r_in],
        fill=(15, 76, 58, 255),
        outline=(16, 185, 129, 140),
        width=max(2, tamanho // 80),
    )

    # Silhueta estilizada de servidor + badge "360"
    head_r = int(r_in * 0.24)
    head_cy = cy - int(r_in * 0.28)
    draw.ellipse(
        [cx - head_r, head_cy - head_r, cx + head_r, head_cy + head_r],
        fill=(255, 255, 255, 255),
    )
    # Ombros em arco
    sh_w = int(r_in * 0.52)
    sh_h = int(r_in * 0.34)
    sh_top = head_cy + head_r + int(r_in * 0.08)
    draw.pieslice(
        [cx - sh_w, sh_top, cx + sh_w, sh_top + sh_h * 2],
        start=180,
        end=360,
        fill=(255, 255, 255, 245),
    )

    # Pílula amarela na base com destaque "360"
    pill_w = int(r_in * 0.92)
    pill_h = int(r_in * 0.36)
    pill_y = cy + int(r_in * 0.26)
    draw.rounded_rectangle(
        [cx - pill_w // 2, pill_y, cx + pill_w // 2, pill_y + pill_h],
        radius=pill_h // 2,
        fill=(250, 204, 21, 255),
    )

    # Texto "360" centralizado na pílula
    font = None
    font_size = max(14, int(pill_h * 0.68))
    for font_name in ("arialbd.ttf", "DejaVuSans-Bold.ttf", "arial.ttf"):
        try:
            font = ImageFont.truetype(font_name, font_size)
            break
        except Exception:
            continue
    if font is None:
        font = ImageFont.load_default()

    txt = "360"
    bbox = draw.textbbox((0, 0), txt, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    draw.text(
        (cx - tw // 2, pill_y + (pill_h - th) // 2 - bbox[1]),
        txt,
        fill=(11, 61, 46, 255),
        font=font,
    )

    return img


def garantir_icones_pwa(static_dir: str) -> Dict[str, str]:
    """Gera (se ausentes) os ícones PNG oficiais do PWA SERVIDOR 360 em static/pwa/."""
    pwa_dir = os.path.join(static_dir, "pwa")
    os.makedirs(pwa_dir, exist_ok=True)

    specs = {
        "icon-192.png": (192, False),
        "icon-512.png": (512, False),
        "icon-maskable-512.png": (512, True),
        "apple-touch-icon.png": (180, False),
    }
    paths = {}
    for filename, (size, maskable) in specs.items():
        full = os.path.join(pwa_dir, filename)
        if not os.path.exists(full):
            img = _desenhar_icone_pwa(size, maskable=maskable)
            img.save(full, format="PNG", optimize=True)
        paths[filename] = full
    return paths


def calcular_idade(dt_nasc: Optional[date]) -> Optional[int]:
    if not dt_nasc:
        return None
    hoje = now_br().date()
    return hoje.year - dt_nasc.year - ((hoje.month, hoje.day) < (dt_nasc.month, dt_nasc.day))


def calcular_completude_cadastral(funcionario: Any) -> Dict[str, Any]:
    """Calcula percentual de preenchimento da documentação do servidor."""
    campos_chave = [
        ("cpf", "CPF"),
        ("rg", "RG"),
        ("data_nasc", "Data de nascimento"),
        ("mae", "Nome da mãe"),
        ("estado_civil", "Estado civil"),
        ("escolaridade", "Escolaridade"),
        ("telefone", "Telefone"),
        ("email", "E-mail"),
        ("endereco", "Endereço"),
        ("bairro", "Bairro"),
        ("cep", "CEP"),
        ("pis", "PIS/PASEP"),
        ("titulo_eleitor", "Título de eleitor"),
        ("banco", "Banco"),
        ("agencia", "Agência"),
        ("conta", "Conta bancária"),
    ]
    preenchidos = 0
    faltantes = []
    for attr, rotulo in campos_chave:
        val = getattr(funcionario, attr, None)
        if val is not None and str(val).strip() != "":
            preenchidos += 1
        else:
            faltantes.append(rotulo)
    total = len(campos_chave)
    pct = int(round((preenchidos / total) * 100)) if total else 100
    return {
        "percentual": pct,
        "preenchidos": preenchidos,
        "total": total,
        "faltantes": faltantes[:5],
    }


def _fmt_val(val: Any, default: str = "Não informado") -> str:
    if val is None:
        return default
    if isinstance(val, bool):
        return "Sim" if val else "Não"
    if isinstance(val, datetime):
        return val.strftime("%d/%m/%Y %H:%M")
    if isinstance(val, date):
        return val.strftime("%d/%m/%Y")
    s = str(val).strip()
    return s if s else default


def _fmt_moeda(valor: Optional[float]) -> str:
    try:
        v = float(valor or 0.0)
    except (TypeError, ValueError):
        return "Não informado"
    if v <= 0:
        return "Não informado"
    txt = f"{v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"R$ {txt}"


def _decodificar_imagem_b64_para_bytes(data_uri: Optional[str]) -> Optional[bytes]:
    if not data_uri or not isinstance(data_uri, str):
        return None
    raw_str = data_uri.strip()
    if "," in raw_str and raw_str.startswith("data:image"):
        raw_str = raw_str.split(",", 1)[1]
    try:
        raw = base64.b64decode(raw_str)
        # Valida e normaliza via Pillow para PNG seguro no ReportLab
        im = Image.open(io.BytesIO(raw)).convert("RGB")
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return None


def gerar_pdf_documentacao_servidor(
    funcionario: Any,
    municipio: Any = None,
    documentos_ged: Optional[List[Any]] = None,
    historico_exercicios: Optional[List[Any]] = None,
    historico_movimentacao: Optional[List[Any]] = None,
    url_validar: str = "",
    logo_path: Optional[str] = None,
) -> bytes:
    """
    Gera o PDF oficial e completo da Ficha Cadastral e Documentação do Servidor
    (ReportLab), contendo foto 3x4, QR Code de validação e 100% dos dados cadastrados.
    """
    import hashlib
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Image as RLImage,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    c_dark = colors.HexColor("#0B3D2E")
    c_mid = colors.HexColor("#14532D")
    c_accent = colors.HexColor("#FACC15")
    c_soft = colors.HexColor("#F2F7F4")
    c_border = colors.HexColor("#D4E2DA")
    c_text = colors.HexColor("#122620")
    c_muted = colors.HexColor("#5B7068")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=13 * mm,
        rightMargin=13 * mm,
        topMargin=12 * mm,
        bottomMargin=14 * mm,
        title=f"Documentacao_{normalizar_cpf(funcionario.cpf) or funcionario.id}",
        author="SERVIDOR 360 — Gestoor360",
    )

    styles = getSampleStyleSheet()
    st_mun = ParagraphStyle("mun", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=13, textColor=colors.white)
    st_sub = ParagraphStyle("sub", parent=styles["Normal"], fontName="Helvetica", fontSize=7.8, leading=10, textColor=colors.HexColor("#D1FAE5"))
    st_badge = ParagraphStyle("bdg", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=c_dark, alignment=TA_CENTER)
    st_sec = ParagraphStyle("sec", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=9.2, leading=12, textColor=c_dark, spaceBefore=6, spaceAfter=3)
    st_lbl = ParagraphStyle("lbl", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=7.2, leading=9, textColor=c_muted)
    st_val = ParagraphStyle("val", parent=styles["Normal"], fontName="Helvetica", fontSize=8.4, leading=10.5, textColor=c_text)
    st_name = ParagraphStyle("nm", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11.5, leading=14, textColor=c_dark)
    st_small = ParagraphStyle("sm", parent=styles["Normal"], fontName="Helvetica", fontSize=7.3, leading=9.5, textColor=c_muted)
    st_foot = ParagraphStyle("ft", parent=styles["Normal"], fontName="Helvetica", fontSize=7, leading=9, textColor=c_muted, alignment=TA_CENTER)

    story: List[Any] = []
    largura_util = A4[0] - 26 * mm

    # --- 1. CABEÇALHO INSTITUCIONAL ---
    mun_nome = getattr(municipio, "nome", None) or "Prefeitura Municipal"
    mun_cnpj = getattr(municipio, "cnpj", None) or ""
    mun_end = getattr(municipio, "endereco", None) or ""
    emissao_str = now_br().strftime("%d/%m/%Y às %H:%M")

    logo_flow = ""
    if logo_path and os.path.exists(logo_path):
        try:
            logo_flow = RLImage(logo_path, width=15 * mm, height=15 * mm, kind="proportional")
        except Exception:
            logo_flow = ""

    header_txt = Paragraph(
        f"<b>{escape(mun_nome.upper())}</b><br/>"
        f"<font size='7.8' color='#D1FAE5'>SERVIDOR 360 • FICHA CADASTRAL E DOCUMENTAÇÃO COMPLETA DO SERVIDOR</font><br/>"
        f"<font size='7' color='#A7F3D0'>{escape(('CNPJ: ' + mun_cnpj + ' • ') if mun_cnpj else '')}Emitido em {escape(emissao_str)} (Horário de Brasília)</font>",
        st_mun,
    )
    badge_tbl = Table([[Paragraph("DOC. OFICIAL<br/>SERVIDOR 360", st_badge)]], colWidths=[28 * mm])
    badge_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c_accent),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    hdr_cols = [18 * mm, largura_util - 48 * mm, 30 * mm] if logo_flow else [largura_util - 30 * mm, 30 * mm]
    hdr_row = [logo_flow, header_txt, badge_tbl] if logo_flow else [header_txt, badge_tbl]
    hdr_tbl = Table([hdr_row], colWidths=hdr_cols)
    hdr_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c_dark),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(hdr_tbl)
    story.append(HRFlowable(width="100%", thickness=2.2, color=c_accent, spaceBefore=0, spaceAfter=6))

    # --- 2. CARTÃO DE IDENTIDADE COM FOTO 3x4 + QR CODE ---
    foto_uri, _ = extrair_foto_referencia(funcionario)
    foto_bytes = _decodificar_imagem_b64_para_bytes(foto_uri)
    foto_el: Any
    if foto_bytes:
        foto_el = RLImage(io.BytesIO(foto_bytes), width=23 * mm, height=28 * mm, kind="proportional")
    else:
        foto_el = Paragraph("<b>SEM FOTO</b>", st_small)

    qr_el: Any = ""
    if url_validar:
        qr_uri = gerar_qr_code_data_uri(url_validar)
        qr_bytes = _decodificar_imagem_b64_para_bytes(qr_uri)
        if qr_bytes:
            qr_el = RLImage(io.BytesIO(qr_bytes), width=24 * mm, height=24 * mm)

    sec_nome = funcionario.secretaria.nome if getattr(funcionario, "secretaria", None) else "—"
    cargo_nome = funcionario.funcao.nome if getattr(funcionario, "funcao", None) else (funcionario.lotacao or "—")
    local_nome = funcionario.local_trabalho.nome if getattr(funcionario, "local_trabalho", None) else (funcionario.lotacao or "—")
    idade = calcular_idade(funcionario.data_nasc)
    idade_txt = f" ({idade} anos)" if idade is not None else ""

    resumo_el = Paragraph(
        f"<b>{escape(_fmt_val(funcionario.nome))}</b><br/>"
        f"<font size='8.5' color='#14532D'><b>{escape(cargo_nome)}</b> • {escape(_fmt_val(funcionario.tipo_vinculo, 'Vínculo não informado'))}</font><br/>"
        f"<font size='7.8' color='#334155'>CPF: <b>{escape(formatar_cpf(funcionario.cpf))}</b> &nbsp;|&nbsp; Matrícula/Vínculo: <b>{escape(_fmt_val(funcionario.num_vinculo, f'#{funcionario.id}'))}</b></font><br/>"
        f"<font size='7.6' color='#475569'>Secretaria: {escape(sec_nome)}<br/>Unidade: {escape(local_nome)}</font><br/>"
        f"<font size='7.5' color='#047857'><b>SITUAÇÃO CADASTRAL: ATIVO • VALIDADO PELO RH</b></font>",
        st_name,
    )

    id_tbl = Table(
        [[foto_el, resumo_el, qr_el]],
        colWidths=[27 * mm, largura_util - 55 * mm, 28 * mm],
    )
    id_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c_soft),
        ("BOX", (0, 0), (-1, -1), 0.7, c_border),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("ALIGN", (2, 0), (2, 0), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(id_tbl)
    story.append(Spacer(1, 4 * mm))

    def _add_section(titulo: str, pares: List[Tuple[str, Any]]):
        story.append(Paragraph(escape(titulo.upper()), st_sec))
        rows = []
        # Organiza em grade de 2 pares por linha (4 colunas: label/val | label/val -> melhor: 2 células empilhadas por linha!)
        for idx in range(0, len(pares), 2):
            chunk = pares[idx : idx + 2]
            linha = []
            for rotulo, valor in chunk:
                cell = Paragraph(
                    f"<font size='6.8' color='#5B7068'><b>{escape(rotulo.upper())}</b></font><br/>"
                    f"<font size='8.4' color='#122620'>{escape(_fmt_val(valor))}</font>",
                    st_val,
                )
                linha.append(cell)
            if len(linha) == 1:
                linha.append(Paragraph("", st_val))
            rows.append(linha)

        t = Table(rows, colWidths=[largura_util / 2.0, largura_util / 2.0], repeatRows=0)
        style_cmds = [
            ("GRID", (0, 0), (-1, -1), 0.45, c_border),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for r_i in range(len(rows)):
            if r_i % 2 == 1:
                style_cmds.append(("BACKGROUND", (0, r_i), (-1, r_i), colors.HexColor("#FAFDFB")))
        t.setStyle(TableStyle(style_cmds))
        story.append(t)
        story.append(Spacer(1, 2.5 * mm))

    # --- SEÇÃO 1: DADOS PESSOAIS ---
    _add_section("1. Dados Pessoais e Identificação", [
        ("Nome Completo", funcionario.nome),
        ("CPF", formatar_cpf(funcionario.cpf)),
        ("Data de Nascimento", (_fmt_val(funcionario.data_nasc) + idade_txt) if funcionario.data_nasc else "Não informado"),
        ("Gênero / Sexo", funcionario.genero),
        ("RG", funcionario.rg),
        ("Órgão Emissor / Expedição", f"{_fmt_val(funcionario.orgao_emissor_rg, '—')} • {_fmt_val(funcionario.data_expedicao_rg, '—')}"),
        ("Estado Civil", funcionario.estado_civil),
        ("Nacionalidade", funcionario.nacionalidade),
        ("Nome da Mãe", funcionario.mae),
        ("Nome do Pai", funcionario.pai),
        ("Escolaridade", funcionario.escolaridade),
        ("Formação / Especialidade", funcionario.especialidade),
        ("Tipo Sanguíneo", funcionario.tipo_sanguineo),
        ("Qtd. de Dependentes", funcionario.qtd_dependentes if funcionario.qtd_dependentes is not None else 0),
        ("Pessoa com Deficiência (PCD)", "Sim" if funcionario.is_pcd else "Não"),
        ("Tipo de Deficiência", funcionario.tipo_deficiencia if funcionario.is_pcd else "Não aplicável"),
    ])

    # --- SEÇÃO 2: DOCUMENTAÇÃO OFICIAL & E-SOCIAL ---
    _add_section("2. Documentação Oficial e e-Social", [
        ("PIS / PASEP", funcionario.pis),
        ("CTPS", funcionario.ctps),
        ("Título de Eleitor", funcionario.titulo_eleitor),
        ("Zona / Seção Eleitoral", f"Zona: {_fmt_val(funcionario.zona_eleitoral, '—')} • Seção: {_fmt_val(funcionario.secao_eleitoral, '—')}"),
        ("CNH", funcionario.cnh),
        ("Código de Validação Cadastral", funcionario.token_validacao),
    ])

    # --- SEÇÃO 3: ENDEREÇO E CONTATOS ---
    _add_section("3. Endereço Residencial e Contatos", [
        ("Telefone / WhatsApp", funcionario.telefone),
        ("E-mail", funcionario.email),
        ("CEP", funcionario.cep),
        ("Logradouro / Endereço", funcionario.endereco),
        ("Bairro", funcionario.bairro),
        ("Cidade / UF", f"{_fmt_val(funcionario.cidade, '—')} / {_fmt_val(funcionario.uf, '—')}"),
        ("Zona de Moradia", funcionario.zona_moradia or "URBANA"),
        ("Povoado / Comunidade", funcionario.povoado_comunidade),
        ("Contato de Emergência (Nome)", funcionario.contato_emergencia_nome),
        ("Contato de Emergência (Telefone)", funcionario.contato_emergencia_tel),
    ])

    # --- SEÇÃO 4: VÍNCULO FUNCIONAL & PORTARIA ---
    pares_vinculo = [
        ("Secretaria", sec_nome),
        ("Unidade / Local de Trabalho", local_nome),
        ("Cargo / Função", cargo_nome),
        ("Tipo de Vínculo", funcionario.tipo_vinculo),
        ("Matrícula / Nº Vínculo", funcionario.num_vinculo or f"#{funcionario.id}"),
        ("Classe / Nível", funcionario.classe),
        ("Jornada de Trabalho", funcionario.jornada_trabalho),
        ("Exercício Atual", funcionario.ano_exercicio_atual or 2026),
        ("Data de Início", funcionario.dt_inicio),
        ("Data de Término Previsto", funcionario.dt_termino or "Indeterminado"),
        ("Remuneração Base", funcionario.remuneracao or _fmt_moeda(funcionario.remuneracao_valor)),
        ("Gratificação", _fmt_moeda(funcionario.gratificacao_valor)),
        ("Nº da Portaria", funcionario.numero_portaria),
        ("Data da Portaria", funcionario.data_portaria),
        ("Referência Contracheque", funcionario.contracheque),
        ("Data do Cadastro no RH", funcionario.data_criacao),
    ]
    if getattr(funcionario, "crianca_assistida", None):
        pares_vinculo.append(("Apoio Pedagógico (Criança Assistida)", funcionario.crianca_assistida))
    _add_section("4. Vínculo Funcional, Lotação e Portaria", pares_vinculo)

    # --- SEÇÃO 5: DADOS BANCÁRIOS ---
    _add_section("5. Dados Bancários", [
        ("Banco", funcionario.banco),
        ("Tipo de Conta", funcionario.tipo_conta),
        ("Agência", funcionario.agencia),
        ("Número da Conta", funcionario.conta),
    ])

    # --- SEÇÃO 6: HISTÓRICO DE EXERCÍCIOS (se houver) ---
    if historico_exercicios:
        story.append(Paragraph("6. HISTÓRICO DE EXERCÍCIOS FUNCIONAIS", st_sec))
        h_rows = [[
            Paragraph("<b>Ano</b>", st_lbl),
            Paragraph("<b>Cargo / Função</b>", st_lbl),
            Paragraph("<b>Unidade</b>", st_lbl),
            Paragraph("<b>Vínculo / Portaria</b>", st_lbl),
            Paragraph("<b>Status</b>", st_lbl),
        ]]
        for h in historico_exercicios:
            h_rows.append([
                Paragraph(escape(_fmt_val(h.ano_exercicio)), st_val),
                Paragraph(escape(_fmt_val(h.funcao_nome, "—")), st_val),
                Paragraph(escape(_fmt_val(h.local_trabalho_nome, "—")), st_val),
                Paragraph(escape(f"{_fmt_val(h.tipo_vinculo, '—')} / {_fmt_val(h.numero_portaria, '—')}"), st_val),
                Paragraph(escape(_fmt_val(h.status, "—")), st_val),
            ])
        ht = Table(h_rows, colWidths=[14 * mm, 48 * mm, 52 * mm, 46 * mm, largura_util - 160 * mm])
        ht.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_soft),
            ("GRID", (0, 0), (-1, -1), 0.45, c_border),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]))
        story.append(ht)
        story.append(Spacer(1, 2.5 * mm))

    # --- SEÇÃO 7: DOSSIÊ DIGITAL (GED) ---
    if documentos_ged:
        story.append(Paragraph("DOSSIÊ DIGITAL DE DOCUMENTOS ARQUIVADOS (GED)", st_sec))
        g_rows = [[
            Paragraph("<b>Tipo de Documento</b>", st_lbl),
            Paragraph("<b>Arquivo</b>", st_lbl),
            Paragraph("<b>Data de Envio</b>", st_lbl),
            Paragraph("<b>Validação RH</b>", st_lbl),
        ]]
        for d in documentos_ged:
            g_rows.append([
                Paragraph(escape((d.tipo_documento or "—").replace("_", " ")), st_val),
                Paragraph(escape(_fmt_val(d.nome_arquivo, "—")), st_val),
                Paragraph(escape(_fmt_val(d.data_upload, "—")), st_val),
                Paragraph("Validado" if d.validado else "Arquivado", st_val),
            ])
        gt = Table(g_rows, colWidths=[48 * mm, 76 * mm, 32 * mm, largura_util - 156 * mm])
        gt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_soft),
            ("GRID", (0, 0), (-1, -1), 0.45, c_border),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]))
        story.append(gt)
        story.append(Spacer(1, 3 * mm))

    # --- RODAPÉ DE AUTENTICIDADE ---
    selo_hash = hashlib.sha256(
        f"{funcionario.id}|{funcionario.cpf}|{funcionario.token_validacao}|{emissao_str}".encode("utf-8")
    ).hexdigest()[:24].upper()

    story.append(Spacer(1, 2 * mm))
    story.append(HRFlowable(width="100%", thickness=0.8, color=c_border, spaceBefore=2, spaceAfter=4))
    story.append(Paragraph(
        f"Documento eletrônico gerado pelo aplicativo oficial <b>SERVIDOR 360</b> ({escape(mun_nome)}).<br/>"
        f"Código de Validação: <b>{escape(_fmt_val(funcionario.token_validacao))}</b> &nbsp;|&nbsp; "
        f"Protocolo de Emissão: <b>{selo_hash}</b><br/>"
        f"{escape('Verifique a autenticidade em: ' + url_validar) if url_validar else ''}"
        f"{('<br/>' + escape(mun_end)) if mun_end else ''}",
        st_foot,
    ))

    doc.build(story)
    return buf.getvalue()

