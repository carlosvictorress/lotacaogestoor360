"""
Módulo Central de Segurança, RBAC (7 Níveis) e Isolamento Multi-Secretarias — Gestoor 360
=========================================================================================
Fornece:
- Matriz de 7 papéis oficiais com compatibilidade retroativa para papéis legados.
- Verificação de permissões granulares e decoradores de rota.
- Guardião de isolamento multi-secretarias (scope_query / can_access_record) contra IDOR.
- Proteção CSRF global para formulários e chamadas AJAX/JSON.
- Proteção contra força bruta (Rate Limit por IP e bloqueio de conta).
- Política de senha forte e headers HTTP de segurança.
"""

from __future__ import annotations

import hmac
import re
import secrets
import time
from collections import defaultdict, deque
from functools import wraps
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from flask import abort, flash, jsonify, redirect, request, session, url_for
from flask_login import current_user

# ==============================================================================
# 1. DEFINIÇÃO DOS 5 NÍVEIS OFICIAIS DE ACESSO (RBAC)
# ==============================================================================

ROLE_METADATA: Dict[str, Dict[str, Any]] = {
    "super_admin": {
        "label": "Super Admin (TI / Desenvolvedor)",
        "short": "Super Admin",
        "scope": "global",
        "level": 100,
        "desc": "Nível supremo de acesso a tudo no sistema (TI e desenvolvedor), único autorizado a excluir registros.",
    },
    "prefeito": {
        "label": "Prefeito Gestor",
        "short": "Prefeito",
        "scope": "global",
        "level": 90,
        "desc": "Acesso global a todos os módulos e secretarias, sem permissão de excluir qualquer registro.",
    },
    "estrategia_eleitoral": {
        "label": "Coordenação Estratégica (Só Eleitoral)",
        "short": "Coord. Estratégica",
        "scope": "global",
        "level": 70,
        "desc": "Acesso exclusivo ao módulo de inteligência eleitoral, locais de votação, seções e lideranças.",
    },
    "secretario": {
        "label": "Secretário(a)",
        "short": "Secretário(a)",
        "scope": "secretaria",
        "level": 50,
        "desc": "Acesso a todos os módulos na sua secretaria (igual ao Prefeito), sem permissão de excluir registros.",
    },
    "rh_secretaria": {
        "label": "RH Secretaria",
        "short": "RH Secretaria",
        "scope": "secretaria",
        "level": 30,
        "desc": "Fichas cadastrais, contratos, Gestoor Sign, organograma, ponto, reconhecimento facial, atestados, rescisões, quantitativos por cargo, folha, apoio pedagógico, lista de servidores e relatórios (sem indicações políticas e sem exclusão).",
    },
}

# Mapeamento de papéis legados para os 5 papéis oficiais sem quebrar usuários existentes no banco
LEGACY_ROLE_MAP = {
    "admin": "super_admin",
    "rh_supervisor": "secretario",
    "auditor": "rh_secretaria",
    "chefe_unidade": "rh_secretaria",
}

PERMISSIONS: Dict[str, set] = {
    # Painéis principais
    "view_admin_panel": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "view_prefeito_panel": {"super_admin", "prefeito", "secretario"},
    # Cadastros estruturais
    "manage_secretarias": {"super_admin", "prefeito"},
    "manage_users": {"super_admin", "prefeito"},
    "manage_funcoes": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "manage_locais": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    # Indicações Políticas / Padrinhos (BLOQUEADO para RH Secretaria)
    "manage_padrinhos": {"super_admin", "prefeito", "secretario", "estrategia_eleitoral"},
    "view_padrinhos": {"super_admin", "prefeito", "secretario", "estrategia_eleitoral"},
    # Backup & Restauração (Prefeito pode gerar/baixar/verificar; excluir backup exige delete_permanently)
    "manage_backup": {"super_admin", "prefeito"},
    # EXCLUSÃO DE QUALQUER REGISTRO — EXCLUSIVO DO SUPER ADMIN (TI / DESENVOLVEDOR)
    "delete_permanently": {"super_admin"},
    # RH, Fichas, Lista de Servidores & Relatórios
    "view_rh": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "write_rh": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "validate_cadastros": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "move_servidores": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "export_rh": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "scan_duplicados": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    # Contratos & Rescisões
    "view_contratos": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "manage_contratos": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "view_rescisoes": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "manage_rescisoes": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    # Gestoor Sign (Assinatura Eletrônica Presencial de Contratos)
    "view_gestoor_sign": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "operate_gestoor_sign": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "cancel_gestoor_sign": {"super_admin", "prefeito", "secretario"},
    "config_gestoor_sign": {"super_admin", "prefeito", "secretario"},
    # Folha de Pagamento & Relatórios
    "view_folha": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    # Unidades de Ponto, Reconhecimento Facial & Atestados Médicos
    "view_ponto": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "manage_biometria": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "view_atestados": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "decide_atestados": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    # App do Servidor (SERVIDOR 360) — Fila de Solicitações de Alteração Cadastral & Reset de Acesso
    "view_solicitacoes_dados": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "decide_solicitacoes_dados": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    # Organograma
    "view_organograma": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "manage_organograma": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    # Dossiê Digital (GED) & Virada de Exercício
    "view_ged": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "manage_ged": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "validate_ged": {"super_admin", "prefeito", "secretario", "rh_secretaria"},
    "manage_virada_exercicio": {"super_admin", "prefeito", "secretario"},
    # Módulo Estratégico Eleitoral (Restrito: Super Admin, Prefeito, Secretário e Coord. Estratégica)
    "view_eleitoral": {"super_admin", "prefeito", "secretario", "estrategia_eleitoral"},
    "manage_eleitoral": {"super_admin", "prefeito", "secretario", "estrategia_eleitoral"},
    # Auditoria Forense
    "view_auditoria": {"super_admin", "prefeito", "secretario"},
}


def normalize_role(user) -> str:
    if not user or not getattr(user, "is_authenticated", False):
        return "anonymous"
    raw_role = (getattr(user, "role", None) or "").strip().lower()
    if raw_role in ROLE_METADATA:
        return raw_role
    if raw_role in LEGACY_ROLE_MAP:
        return LEGACY_ROLE_MAP[raw_role]
    if getattr(user, "is_admin", False):
        return "super_admin"
    return "rh_secretaria"


def get_role_label(role_or_user) -> str:
    if isinstance(role_or_user, str):
        r = LEGACY_ROLE_MAP.get(role_or_user, role_or_user)
    else:
        r = normalize_role(role_or_user)
    return ROLE_METADATA.get(r, {}).get("label", r.upper())


def get_role_scope(user) -> str:
    r = normalize_role(user)
    return ROLE_METADATA.get(r, {}).get("scope", "secretaria")


def has_global_scope(user) -> bool:
    return get_role_scope(user) == "global"


def is_super_admin(user) -> bool:
    return normalize_role(user) == "super_admin"


def is_gestor_global(user) -> bool:
    return normalize_role(user) in ("super_admin", "prefeito")


def has_permission(user, permission: str) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    role = normalize_role(user)
    allowed = PERMISSIONS.get(permission, set())
    return role in allowed


def get_default_home_endpoint(user) -> str:
    role = normalize_role(user)
    if role == "prefeito":
        return "painel_prefeito"
    if role == "estrategia_eleitoral":
        return "eleitoral_estrategia"
    if role in ("super_admin", "secretario", "rh_secretaria"):
        return "admin_dashboard"
    return "sistema"


# ==============================================================================
# 2. GUARDIÃO DE ISOLAMENTO MULTI-SECRETARIAS (ANTI-IDOR)
# ==============================================================================

def get_user_municipio_id(user) -> Optional[int]:
    """Retorna o municipio_id efetivo do usuário (direto ou via secretaria vinculada)."""
    if not user or not getattr(user, "is_authenticated", False):
        return None
    mun_id = getattr(user, "municipio_id", None)
    if mun_id is not None:
        return int(mun_id)
    sec = getattr(user, "secretaria", None)
    if sec is not None and getattr(sec, "municipio_id", None) is not None:
        return int(sec.municipio_id)
    return None


def scope_query(query, model, user):
    """
    Aplica filtro automático de isolamento multi-tenant:
    Município -> Secretaria -> Unidade.
    - super_admin sem municipio_id (Master plataforma) vê todos os municípios.
    - Demais usuários com municipio_id ficam estritamente isolados ao seu município.
    - Secretários e RH veem APENAS registros da sua secretaria_id.
    - Chefe de Unidade vê APENAS registros da sua secretaria_id e local_trabalho_id.
    """
    role = normalize_role(user)
    user_mun_id = get_user_municipio_id(user)

    if hasattr(model, "municipio_id"):
        if role == "super_admin" and user_mun_id is None:
            pass
        elif user_mun_id is not None:
            query = query.filter(model.municipio_id == user_mun_id)
        elif role != "super_admin":
            return query.filter(model.municipio_id == -1)

    scope = get_role_scope(user)
    if scope == "global":
        return query

    sec_id = getattr(user, "secretaria_id", None)
    if hasattr(model, "secretaria_id"):
        if sec_id is None:
            # Usuário de escopo restrito sem secretaria atribuída não vê nada (fail-closed)
            return query.filter(model.secretaria_id == -1)
        query = query.filter(model.secretaria_id == sec_id)

    if scope == "unidade":
        local_id = getattr(user, "local_trabalho_id", None)
        if hasattr(model, "local_trabalho_id"):
            if local_id is None:
                return query.filter(model.local_trabalho_id == -1)
            query = query.filter(model.local_trabalho_id == local_id)
        elif model.__tablename__ == "local_trabalho":
            if local_id is None:
                return query.filter(model.id == -1)
            query = query.filter(model.id == local_id)

    return query


def can_access_record(user, record) -> bool:
    """
    Verifica se o usuário tem direito de acessar/modificar um registro específico.
    Garante isolamento estrito entre municípios, secretarias e unidades.
    """
    if not user or not getattr(user, "is_authenticated", False) or record is None:
        return False

    role = normalize_role(user)
    user_mun_id = get_user_municipio_id(user)

    # 1. Isolamento Multi-Tenant por Município
    rec_mun_id = getattr(record, "municipio_id", None)
    if rec_mun_id is None and hasattr(record, "secretaria") and record.secretaria is not None:
        rec_mun_id = getattr(record.secretaria, "municipio_id", None)
    if rec_mun_id is None and hasattr(record, "contrato") and record.contrato is not None:
        rec_mun_id = getattr(record.contrato, "municipio_id", None)
    if rec_mun_id is None and hasattr(record, "funcionario") and record.funcionario is not None:
        rec_mun_id = getattr(record.funcionario, "municipio_id", None)

    if role != "super_admin" or user_mun_id is not None:
        if rec_mun_id is not None:
            if user_mun_id is None or int(rec_mun_id) != int(user_mun_id):
                return False
        elif hasattr(record, "municipio_id") and role != "super_admin":
            return False

    scope = get_role_scope(user)
    if scope == "global":
        return True

    user_sec_id = getattr(user, "secretaria_id", None)
    if user_sec_id is None:
        return False

    # 2. Descobre a secretaria_id do registro (diretamente ou via relacionamento)
    rec_sec_id = getattr(record, "secretaria_id", None)
    if rec_sec_id is None and hasattr(record, "contrato") and record.contrato is not None:
        rec_sec_id = getattr(record.contrato, "secretaria_id", None)
    if rec_sec_id is None and hasattr(record, "funcionario") and record.funcionario is not None:
        rec_sec_id = getattr(record.funcionario, "secretaria_id", None)
    if rec_sec_id is None and hasattr(record, "exercicio") and record.exercicio is not None:
        rec_sec_id = getattr(record.exercicio, "secretaria_id", None)
    if rec_sec_id is None and hasattr(record, "node") and record.node is not None and getattr(record.node, "exercicio", None) is not None:
        rec_sec_id = getattr(record.node.exercicio, "secretaria_id", None)

    if rec_sec_id is not None and int(rec_sec_id) != int(user_sec_id):
        return False
    # Se o registro tem coluna secretaria_id mas veio None, somente global pode mexer
    if hasattr(record, "secretaria_id") and rec_sec_id is None:
        return False

    if scope == "unidade":
        user_local_id = getattr(user, "local_trabalho_id", None)
        if user_local_id is None:
            return False
        rec_local_id = getattr(record, "local_trabalho_id", None)
        if rec_local_id is None and hasattr(record, "funcionario") and record.funcionario is not None:
            rec_local_id = getattr(record.funcionario, "local_trabalho_id", None)
        if rec_local_id is None and record.__class__.__name__ == "LocalTrabalho":
            rec_local_id = getattr(record, "id", None)
        if rec_local_id is None or int(rec_local_id) != int(user_local_id):
            return False

    return True


def require_permission(permission: str, api: bool = False) -> Callable:
    """Decorador de proteção de rota por permissão granular."""
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                if api:
                    return jsonify({"success": False, "message": "Sessão expirada. Faça login novamente."}), 401
                return redirect(url_for("login"))

            if not has_permission(current_user, permission):
                if api:
                    return jsonify({
                        "success": False,
                        "message": "Acesso negado: seu nível de acesso não permite esta operação.",
                    }), 403
                flash("Acesso negado: seu nível de acesso não permite esta área ou operação.", "error")
                return redirect(url_for(get_default_home_endpoint(current_user)))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ==============================================================================
# 3. PROTEÇÃO CSRF GLOBAL
# ==============================================================================

CSRF_EXEMPT_PREFIXES = (
    "/ponto/",
    "/ponto-facial",
    "/api/ping_session",
)


def get_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    # Mantém compatibilidade com a chave do módulo de backup
    session["backup_csrf_token"] = token
    return token


def validate_csrf_request() -> bool:
    expected = session.get("_csrf_token") or session.get("backup_csrf_token")
    if not expected:
        return False
    provided = (
        request.headers.get("X-CSRF-Token")
        or request.headers.get("X-CSRFToken")
        or request.form.get("csrf_token")
    )
    if not provided and request.is_json:
        body = request.get_json(silent=True) or {}
        if isinstance(body, dict):
            provided = body.get("csrf_token")
    return bool(provided and hmac.compare_digest(str(expected), str(provided)))


def is_csrf_exempt(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in CSRF_EXEMPT_PREFIXES)


# ==============================================================================
# 4. POLÍTICA DE SENHA FORTE & PROTEÇÃO CONTRA FORÇA BRUTA (RATE LIMIT)
# ==============================================================================

def validate_password_strength(password: str) -> Tuple[bool, str]:
    if not password or len(password) < 8:
        return False, "A senha deve ter no mínimo 8 caracteres."
    if not re.search(r"[A-Za-z]", password):
        return False, "A senha deve conter pelo menos uma letra."
    if not re.search(r"\d", password):
        return False, "A senha deve conter pelo menos um número."
    return True, "OK"


class InMemoryRateLimiter:
    """Rate limiter leve por janela deslizante para proteger endpoints de login contra força bruta."""

    def __init__(self) -> None:
        self._hits: Dict[str, deque] = defaultdict(deque)

    def is_limited(self, key: str, max_attempts: int = 12, window_seconds: int = 300) -> Tuple[bool, int]:
        now = time.monotonic()
        dq = self._hits[key]
        while dq and (now - dq[0]) > window_seconds:
            dq.popleft()
        if len(dq) >= max_attempts:
            retry_after = int(window_seconds - (now - dq[0])) + 1
            return True, max(retry_after, 1)
        return False, 0

    def register_failure(self, key: str) -> None:
        self._hits[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)


login_rate_limiter = InMemoryRateLimiter()


# ==============================================================================
# 5. PARSER FINANCEIRO SEGURO (STRING BRL -> FLOAT)
# ==============================================================================

def parse_remuneracao_float(valor_str: Any) -> float:
    if valor_str is None:
        return 0.0
    if isinstance(valor_str, (int, float)):
        return float(valor_str)
    s = str(valor_str).strip()
    if not s:
        return 0.0
    s = s.replace("R$", "").replace(" ", "")
    # Formato BR "2.500,50" vs US "2500.50"
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    s = re.sub(r"[^0-9.\-]", "", s)
    try:
        return round(float(s), 2)
    except ValueError:
        return 0.0


# ==============================================================================
# 6. HEADERS HTTP DE SEGURANÇA
# ==============================================================================

def apply_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(self), camera=(self), microphone=()",
    )
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response
