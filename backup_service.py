"""
Módulo de Backup & Restauração Completo (Full System) — Gestoor 360
===================================================================
- Exporta 100% das tabelas do banco de dados em ordem de integridade referencial
  (com serialização tipada portável entre PostgreSQL e SQLite).
- Empacota 100% das mídias do sistema (fotos de ponto, logos, timbres, anexos futuros).
- Valida integridade com SHA-256 por tabela e por arquivo no manifesto.
- Criptografa o pacote inteiro com AES-256-GCM + PBKDF2-HMAC-SHA256 (.g360bkp).
- Realiza pré-inspeção segura antes de restaurar, cria auto-snapshot de segurança
  pré-restauração e executa restauração transacional com sincronização de sequências.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import posixpath
import shutil
import tempfile
import uuid
import zipfile
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import pytz
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import text

BACKUP_MAGIC = b"G360BKP1"
BACKUP_FORMAT_VERSION = "1.0"
PBKDF2_ITERATIONS = 300_000
SALT_LEN = 16
NONCE_LEN = 12

# Tabela excluída do wipe/restore para preservar histórico e snapshot pré-restore do servidor
EXCLUDED_TABLES = {"backup_historico"}

# Rótulos amigáveis para exibição no painel de inventário e prévia de restauração
TABLE_LABELS = {
    "secretaria": "Secretarias",
    "funcao": "Funções / Cargos",
    "local_trabalho": "Locais de Trabalho (Unidades)",
    "padrinho": "Padrinhos / Indicadores",
    "user": "Usuários e Acessos",
    "funcionario": "Servidores (Fichas Completas)",
    "historico_lotacao": "Histórico de Movimentações",
    "registro_ponto": "Registros de Ponto Eletrônico",
    "rescisao_historico": "Histórico de Rescisões",
    "contrato_gerado": "Contratos Administrativos",
    "justificativas_falta": "Atestados e Justificativas",
    "organograma_exercicio": "Organograma — Exercícios",
    "organograma_node": "Organograma — Cargos / Unidades",
    "organograma_servidor": "Organograma — Nomeações / Portarias",
    "organograma_historico": "Organograma — Histórico de Atos",
    "local_votacao": "Locais de Votação (Eleitoral)",
    "documento_servidor": "Dossiê Digital de Documentos (GED)",
    "historico_vinculo_exercicio": "Histórico de Exercícios (2026/2027)",
    "municipio": "Municípios (Multi-Tenant)",
    "configuracao_gestoor_sign": "Gestoor Sign — Configurações Municipais",
    "assinatura_contrato": "Gestoor Sign — Assinaturas Eletrônicas",
    "assinatura_sms_otp": "Gestoor Sign — Desafios OTP SMS",
    "assinatura_evento": "Gestoor Sign — Trilha de Eventos",
    "assinatura_documento_arquivo": "Gestoor Sign — PDFs Selados e Evidências",
    "log_auditoria": "Logs de Auditoria Forense",
}

ALLOWED_MEDIA_DIRS = (
    "static/ponto_fotos",
    "static/timbres",
    "static/fotos",
    "static/uploads",
    "instance/uploads",
    "storage/uploads",
    "storage/ged",
)

ALLOWED_STATIC_ROOT_EXTS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".gif",
    ".svg",
    ".ico",
    ".pdf",
}

ALLOWED_RESTORE_PREFIXES = (
    "static/",
    "instance/uploads/",
    "storage/uploads/",
    "storage/ged/",
)


class BackupError(Exception):
    """Erro operacional controlado do módulo de backup/restauração."""


class BackupAuthError(BackupError):
    """Senha de criptografia incorreta ou arquivo adulterado."""


def _now_br() -> datetime:
    tz = pytz.timezone("America/Sao_Paulo")
    return datetime.now(tz)


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password or len(password) < 6:
        raise BackupError("A senha do backup deve possuir pelo menos 6 caracteres.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(raw_bytes: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aad = BACKUP_MAGIC + salt
    ciphertext = AESGCM(key).encrypt(nonce, raw_bytes, aad)
    return BACKUP_MAGIC + salt + nonce + ciphertext


def decrypt_payload(encrypted_bytes: bytes, password: str) -> bytes:
    min_len = len(BACKUP_MAGIC) + SALT_LEN + NONCE_LEN + 16
    if not encrypted_bytes or len(encrypted_bytes) < min_len:
        raise BackupError("Arquivo inválido ou corrompido (tamanho insuficiente).")
    if encrypted_bytes[: len(BACKUP_MAGIC)] != BACKUP_MAGIC:
        raise BackupError(
            "Formato de arquivo não reconhecido. Envie um arquivo oficial '.g360bkp' gerado pelo Gestoor 360."
        )

    offset = len(BACKUP_MAGIC)
    salt = encrypted_bytes[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = encrypted_bytes[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = encrypted_bytes[offset:]

    key = _derive_key(password, salt)
    aad = BACKUP_MAGIC + salt
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise BackupAuthError(
            "Senha do backup incorreta ou arquivo corrompido/adulterado."
        )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _serialize_value(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float, str)):
        return val
    if isinstance(val, datetime):
        return {"__t__": "datetime", "v": val.isoformat()}
    if isinstance(val, date):
        return {"__t__": "date", "v": val.isoformat()}
    if isinstance(val, Decimal):
        return {"__t__": "decimal", "v": str(val)}
    if isinstance(val, (bytes, bytearray, memoryview)):
        return {"__t__": "bytes", "v": base64.b64encode(bytes(val)).decode("ascii")}
    return str(val)


def _deserialize_value(val: Any, col_type: Any = None) -> Any:
    if val is None:
        return None
    if isinstance(val, dict) and "__t__" in val and "v" in val:
        t = val["__t__"]
        raw = val["v"]
        if t == "datetime":
            return datetime.fromisoformat(raw)
        if t == "date":
            return date.fromisoformat(raw)
        if t == "decimal":
            return Decimal(raw)
        if t == "bytes":
            return base64.b64decode(raw.encode("ascii"))
        return raw

    # Conversão defensiva caso tipos SQLite/Postgres divirjam (ex.: string ISO em coluna Date/DateTime)
    if col_type is not None and isinstance(val, str):
        py_type = None
        try:
            py_type = col_type.python_type
        except Exception:
            py_type = None
        if py_type is datetime:
            try:
                return datetime.fromisoformat(val)
            except Exception:
                return val
        if py_type is date:
            try:
                return date.fromisoformat(val[:10])
            except Exception:
                return val
    return val


def _is_safe_media_path(rel_posix_path: str) -> bool:
    if not rel_posix_path or rel_posix_path.startswith("/") or "\\" in rel_posix_path:
        return False
    norm = posixpath.normpath(rel_posix_path)
    if norm.startswith("..") or "/../" in f"/{norm}/" or norm in (".", ".."):
        return False
    if norm != rel_posix_path:
        return False
    # Bloqueia scripts/código na pasta static
    if norm.startswith("static/js/") or norm.startswith("static/css/"):
        return False
    if norm.startswith("instance/backups/"):
        return False
    return any(norm.startswith(prefix) for prefix in ALLOWED_RESTORE_PREFIXES)


def collect_media_files(app_root: str) -> List[Tuple[str, str, int]]:
    """
    Retorna lista de (rel_posix_path, abs_path, size_bytes) de todos os arquivos
    de mídia do sistema (fotos de ponto, logos, timbres e futuros anexos GED).
    """
    collected: Dict[str, Tuple[str, int]] = {}

    # 1. Diretórios dedicados de mídia
    for rel_dir in ALLOWED_MEDIA_DIRS:
        abs_dir = os.path.join(app_root, *rel_dir.split("/"))
        if not os.path.isdir(abs_dir):
            continue
        for dirpath, _, filenames in os.walk(abs_dir):
            for fname in sorted(filenames):
                abs_file = os.path.join(dirpath, fname)
                if not os.path.isfile(abs_file):
                    continue
                rel = os.path.relpath(abs_file, app_root).replace("\\", "/")
                if _is_safe_media_path(rel):
                    collected[rel] = (abs_file, os.path.getsize(abs_file))

    # 2. Imagens / timbres na raiz de static/
    static_root = os.path.join(app_root, "static")
    if os.path.isdir(static_root):
        for entry in sorted(os.listdir(static_root)):
            abs_file = os.path.join(static_root, entry)
            if not os.path.isfile(abs_file):
                continue
            ext = os.path.splitext(entry)[1].lower()
            if ext in ALLOWED_STATIC_ROOT_EXTS:
                rel = f"static/{entry}"
                if _is_safe_media_path(rel):
                    collected[rel] = (abs_file, os.path.getsize(abs_file))

    return [(rel, info[0], info[1]) for rel, info in sorted(collected.items())]


def get_backup_dir(app_root: str) -> str:
    bkp_dir = os.path.join(app_root, "instance", "backups")
    os.makedirs(bkp_dir, exist_ok=True)
    return bkp_dir


def get_staging_dir(app_root: str) -> str:
    stg_dir = os.path.join(get_backup_dir(app_root), "_staging")
    os.makedirs(stg_dir, exist_ok=True)
    return stg_dir


def cleanup_old_staging(app_root: str, max_age_seconds: int = 3600) -> None:
    stg_dir = get_staging_dir(app_root)
    now_ts = datetime.utcnow().timestamp()
    for fname in os.listdir(stg_dir):
        fpath = os.path.join(stg_dir, fname)
        try:
            if os.path.isfile(fpath) and (now_ts - os.path.getmtime(fpath)) > max_age_seconds:
                os.remove(fpath)
        except OSError:
            pass


def get_target_tables(db) -> List[Any]:
    """Retorna todas as tabelas SQLAlchemy em ordem de dependência (exceto backup_historico)."""
    inspector = sa_inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    return [
        t
        for t in db.metadata.sorted_tables
        if t.name not in EXCLUDED_TABLES and t.name in existing_tables
    ]


def get_system_inventory(db, app_root: str) -> Dict[str, Any]:
    """Resumo em tempo real de tudo que existe no banco e nas mídias do sistema."""
    tables = get_target_tables(db)
    tables_info = []
    total_records = 0

    with db.engine.connect() as conn:
        for table in tables:
            count = conn.execute(text(f'SELECT COUNT(*) FROM "{table.name}"')).scalar() or 0
            total_records += int(count)
            tables_info.append(
                {
                    "name": table.name,
                    "label": TABLE_LABELS.get(table.name, table.name),
                    "count": int(count),
                }
            )

    media_files = collect_media_files(app_root)
    total_media_bytes = sum(item[2] for item in media_files)

    dialect_name = db.engine.dialect.name
    engine_label = (
        "PostgreSQL (Produção / Nuvem)"
        if "postgres" in dialect_name
        else f"{dialect_name.upper()} (Local)"
    )

    return {
        "dialect": dialect_name,
        "engine_label": engine_label,
        "tables": tables_info,
        "total_tables": len(tables_info),
        "total_records": total_records,
        "total_media_files": len(media_files),
        "total_media_bytes": total_media_bytes,
    }


def create_full_backup(
    db,
    app_root: str,
    password: str,
    created_by: str,
    prefix: str = "gestoor360_backup",
    observacao: str = "",
) -> Dict[str, Any]:
    """
    Gera um backup completo criptografado (.g360bkp) contendo:
    - Todas as tabelas do banco de dados em JSONL tipado
    - Todos os arquivos de mídia do sistema
    - Manifesto completo com contagens e hashes SHA-256
    """
    agora_br = _now_br()
    timestamp_slug = agora_br.strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp_slug}.g360bkp"

    tables = get_target_tables(db)
    media_files = collect_media_files(app_root)

    zip_buffer = io.BytesIO()
    tables_manifest: Dict[str, Dict[str, Any]] = {}
    media_manifest: Dict[str, Dict[str, Any]] = {}
    total_records = 0

    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        # 1. Exportação consistente de todas as tabelas
        with db.engine.connect() as conn:
            for table in tables:
                col_names = [c.name for c in table.columns]
                rows = conn.execute(table.select()).mappings().all()

                lines = []
                for row in rows:
                    record = {col: _serialize_value(row[col]) for col in col_names}
                    lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))

                content_bytes = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
                arc_path = f"database/{table.name}.jsonl"
                zf.writestr(arc_path, content_bytes)

                row_count = len(rows)
                total_records += row_count
                tables_manifest[table.name] = {
                    "label": TABLE_LABELS.get(table.name, table.name),
                    "rows": row_count,
                    "columns": col_names,
                    "sha256": _sha256_bytes(content_bytes),
                    "size_bytes": len(content_bytes),
                }

        # 2. Empacotamento de todas as mídias físicas
        total_media_bytes = 0
        for rel_path, abs_path, _ in media_files:
            with open(abs_path, "rb") as f_media:
                media_bytes = f_media.read()
            arc_path = f"media/{rel_path}"
            zf.writestr(arc_path, media_bytes)
            media_size = len(media_bytes)
            total_media_bytes += media_size
            media_manifest[rel_path] = {
                "size_bytes": media_size,
                "sha256": _sha256_bytes(media_bytes),
            }

        # 3. Manifesto oficial de integridade
        manifest = {
            "app": "Gestoor 360",
            "format_version": BACKUP_FORMAT_VERSION,
            "created_at_br": agora_br.strftime("%d/%m/%Y %H:%M:%S"),
            "created_at_iso": agora_br.isoformat(),
            "created_by": created_by,
            "observacao": observacao,
            "source_dialect": db.engine.dialect.name,
            "table_order": [t.name for t in tables],
            "tables": tables_manifest,
            "media": media_manifest,
            "totals": {
                "tables": len(tables_manifest),
                "records": total_records,
                "media_files": len(media_manifest),
                "media_bytes": total_media_bytes,
            },
        }
        zf.writestr(
            "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
        )

    zip_bytes = zip_buffer.getvalue()
    encrypted_bytes = encrypt_payload(zip_bytes, password)
    file_sha256 = _sha256_bytes(encrypted_bytes)

    bkp_dir = get_backup_dir(app_root)
    dest_path = os.path.join(bkp_dir, filename)
    with open(dest_path, "wb") as f_out:
        f_out.write(encrypted_bytes)

    return {
        "filename": filename,
        "abs_path": dest_path,
        "size_bytes": len(encrypted_bytes),
        "sha256": file_sha256,
        "manifest": manifest,
    }


def inspect_backup_bytes(
    db,
    encrypted_bytes: bytes,
    password: str,
) -> Tuple[Dict[str, Any], bytes]:
    """
    Descriptografa e valida integralmente um arquivo .g360bkp:
    - Verifica assinatura e tag AES-256-GCM
    - Verifica integridade ZIP
    - Verifica SHA-256 de CADA tabela e CADA arquivo de mídia
    - Verifica compatibilidade com o schema atual e compara contagens atuais vs backup
    """
    zip_bytes = decrypt_payload(encrypted_bytes, password)

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r")
    except zipfile.BadZipFile:
        raise BackupError("O conteúdo descriptografado não é um pacote ZIP válido.")

    with zf:
        if "manifest.json" not in zf.namelist():
            raise BackupError("Manifesto de integridade (manifest.json) ausente no pacote.")

        try:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        except Exception as exc:
            raise BackupError(f"Erro ao ler manifesto do backup: {exc}")

        if manifest.get("app") != "Gestoor 360":
            raise BackupError("Este arquivo de backup não pertence ao sistema Gestoor 360.")

        # Valida SHA-256 de cada tabela
        tables_manifest = manifest.get("tables", {})
        for tname, meta in tables_manifest.items():
            arc_path = f"database/{tname}.jsonl"
            if arc_path not in zf.namelist():
                raise BackupError(f"Tabela '{tname}' listada no manifesto está ausente no pacote.")
            raw_tbl = zf.read(arc_path)
            if _sha256_bytes(raw_tbl) != meta.get("sha256"):
                raise BackupError(f"Falha de integridade SHA-256 na tabela '{tname}'. Arquivo corrompido.")

        # Valida SHA-256 e segurança de caminho de cada arquivo de mídia
        media_manifest = manifest.get("media", {})
        for rel_path, meta in media_manifest.items():
            if not _is_safe_media_path(rel_path):
                raise BackupError(f"Caminho de mídia não permitido detectado no pacote: {rel_path}")
            arc_path = f"media/{rel_path}"
            if arc_path not in zf.namelist():
                raise BackupError(f"Arquivo de mídia '{rel_path}' ausente no pacote.")
            raw_media = zf.read(arc_path)
            if _sha256_bytes(raw_media) != meta.get("sha256"):
                raise BackupError(f"Falha de integridade SHA-256 na mídia '{rel_path}'.")

    # Compara com o estado atual do banco
    current_tables = {t.name: t for t in get_target_tables(db)}
    comparison = []
    warnings = []

    with db.engine.connect() as conn:
        for tname in manifest.get("table_order", list(tables_manifest.keys())):
            meta = tables_manifest.get(tname, {})
            bkp_rows = int(meta.get("rows", 0))
            if tname in current_tables:
                cur_rows = int(
                    conn.execute(text(f'SELECT COUNT(*) FROM "{tname}"')).scalar() or 0
                )
                cur_cols = {c.name for c in current_tables[tname].columns}
                bkp_cols = set(meta.get("columns") or [])
                if bkp_cols:
                    new_cols = sorted(cur_cols - bkp_cols)
                    dropped_cols = sorted(bkp_cols - cur_cols)
                    if new_cols:
                        warnings.append(
                            f"Tabela '{tname}' é de versão anterior: {len(new_cols)} nova(s) coluna(s) ({', '.join(new_cols[:4])}{'...' if len(new_cols) > 4 else ''}) receberão valores padrão/backfill automático."
                        )
                    if dropped_cols:
                        warnings.append(
                            f"Tabela '{tname}' possui coluna(s) antiga(s) não usadas nesta versão ({', '.join(dropped_cols[:4])}) que serão ignoradas com segurança."
                        )
            else:
                cur_rows = None
                warnings.append(
                    f"Tabela '{tname}' existe no backup, mas não existe neste schema (será ignorada)."
                )
            comparison.append(
                {
                    "name": tname,
                    "label": meta.get("label") or TABLE_LABELS.get(tname, tname),
                    "backup_rows": bkp_rows,
                    "current_rows": cur_rows,
                }
            )

    for cur_tname in current_tables:
        if cur_tname not in tables_manifest:
            warnings.append(
                f"Tabela '{cur_tname}' existe no sistema atual mas não no backup (ficará vazia após restaurar)."
            )

    preview = {
        "manifest": manifest,
        "comparison": comparison,
        "warnings": warnings,
        "sha256": _sha256_bytes(encrypted_bytes),
        "size_bytes": len(encrypted_bytes),
    }
    return preview, zip_bytes


def stage_uploaded_backup(app_root: str, encrypted_bytes: bytes) -> str:
    """Salva temporariamente um backup já inspecionado para o passo de confirmação."""
    cleanup_old_staging(app_root)
    token = uuid.uuid4().hex
    stg_path = os.path.join(get_staging_dir(app_root), f"{token}.g360bkp")
    with open(stg_path, "wb") as f_out:
        f_out.write(encrypted_bytes)
    return token


def read_staged_backup(app_root: str, token: str) -> Tuple[bytes, str]:
    if not token or not token.isalnum() or len(token) > 64:
        raise BackupError("Token de restauração inválido ou expirado.")
    stg_path = os.path.join(get_staging_dir(app_root), f"{token}.g360bkp")
    if not os.path.isfile(stg_path):
        raise BackupError(
            "Sessão de restauração expirada. Envie e inspecione o arquivo de backup novamente."
        )
    with open(stg_path, "rb") as f_in:
        return f_in.read(), stg_path


def _find_self_fk_columns(table) -> List[str]:
    cols = []
    for col in table.columns:
        for fk in col.foreign_keys:
            if fk.column.table.name == table.name:
                cols.append(col.name)
                break
    return cols


def _reset_sequences(conn, dialect_name: str, tables: List[Any]) -> None:
    """Sincroniza sequências autoincremento (PostgreSQL e SQLite) após restaurar IDs explícitos."""
    if "postgres" in dialect_name:
        for table in tables:
            pk_cols = list(table.primary_key.columns)
            if len(pk_cols) != 1:
                continue
            pk_col = pk_cols[0]
            try:
                is_int = pk_col.type.python_type is int
            except Exception:
                is_int = False
            if not is_int:
                continue

            nested = conn.begin_nested()
            try:
                seq_name = conn.execute(
                    text("SELECT pg_get_serial_sequence(:tname, :cname)"),
                    {"tname": table.name, "cname": pk_col.name},
                ).scalar()
                if seq_name:
                    max_val = conn.execute(
                        text(f'SELECT MAX("{pk_col.name}") FROM "{table.name}"')
                    ).scalar()
                    if max_val is None:
                        conn.execute(
                            text("SELECT setval(:seq, 1, false)"),
                            {"seq": seq_name},
                        )
                    else:
                        conn.execute(
                            text("SELECT setval(:seq, :val, true)"),
                            {"seq": seq_name, "val": int(max_val)},
                        )
                nested.commit()
            except Exception:
                nested.rollback()

    elif dialect_name == "sqlite":
        has_seq = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
        ).fetchone()
        if not has_seq:
            return
        for table in tables:
            pk_cols = list(table.primary_key.columns)
            if len(pk_cols) != 1:
                continue
            pk_col = pk_cols[0]
            max_val = conn.execute(
                text(f'SELECT MAX("{pk_col.name}") FROM "{table.name}"')
            ).scalar()
            conn.execute(
                text("DELETE FROM sqlite_sequence WHERE name = :tname"),
                {"tname": table.name},
            )
            if max_val is not None:
                conn.execute(
                    text("INSERT INTO sqlite_sequence (name, seq) VALUES (:tname, :seq)"),
                    {"tname": table.name, "seq": int(max_val)},
                )


def _restore_media_files_atomic(app_root: str, zf: zipfile.ZipFile, manifest: Dict[str, Any]) -> int:
    """
    Restaura todos os arquivos de mídia de forma segura.
    Em caso de falha, mantém os arquivos anteriores preservados via backup temporário.
    """
    media_manifest = manifest.get("media", {})
    if not media_manifest:
        return 0

    temp_old_dir = tempfile.mkdtemp(prefix="g360_media_old_")
    restored_paths: List[str] = []
    backed_up_paths: List[Tuple[str, str]] = []

    try:
        # 1. Extrai e valida todos os bytes primeiro em memória/temp
        extracted_items: List[Tuple[str, bytes]] = []
        for rel_path, meta in media_manifest.items():
            if not _is_safe_media_path(rel_path):
                raise BackupError(f"Caminho inseguro detectado: {rel_path}")
            data = zf.read(f"media/{rel_path}")
            if _sha256_bytes(data) != meta.get("sha256"):
                raise BackupError(f"Hash SHA-256 divergente para {rel_path}.")
            extracted_items.append((rel_path, data))

        # 2. Faz cópia temporária dos arquivos existentes que serão substituídos
        for rel_path, _ in extracted_items:
            abs_dest = os.path.join(app_root, *rel_path.split("/"))
            if os.path.isfile(abs_dest):
                abs_bak = os.path.join(temp_old_dir, *rel_path.split("/"))
                os.makedirs(os.path.dirname(abs_bak), exist_ok=True)
                shutil.copy2(abs_dest, abs_bak)
                backed_up_paths.append((abs_dest, abs_bak))

        # 3. Grava novos arquivos
        for rel_path, data in extracted_items:
            abs_dest = os.path.join(app_root, *rel_path.split("/"))
            os.makedirs(os.path.dirname(abs_dest), exist_ok=True)
            with open(abs_dest, "wb") as f_out:
                f_out.write(data)
            restored_paths.append(abs_dest)

        return len(extracted_items)
    except Exception:
        # Rollback dos arquivos de mídia em caso de erro
        for abs_dest, abs_bak in backed_up_paths:
            try:
                shutil.copy2(abs_bak, abs_dest)
            except OSError:
                pass
        raise
    finally:
        shutil.rmtree(temp_old_dir, ignore_errors=True)


def restore_full_backup(
    db,
    app_root: str,
    encrypted_bytes: bytes,
    password: str,
    restored_by: str,
    safety_password: Optional[str] = None,
    post_restore_hook: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Restaura o sistema completo de forma transacional e à prova de falhas:
    1. Valida e verifica integridade 100% do arquivo .g360bkp.
    2. Gera automaticamente um Backup de Segurança (PRE_RESTORE) do estado atual.
    3. Em uma única transação de banco:
       - Limpa todas as tabelas em ordem reversa de FKs (zerando auto-FKs antes)
       - Insere todos os registros preservando IDs originais (2 passos para auto-FKs)
       - Sincroniza sequências PostgreSQL / SQLite
    4. Restaura todas as mídias físicas.
    """
    # 1. Validação rigorosa antes de tocar em qualquer dado
    preview, zip_bytes = inspect_backup_bytes(db, encrypted_bytes, password)
    manifest = preview["manifest"]

    # 2. Cria Auto-Snapshot de Segurança antes da restauração
    safety_pwd = safety_password or password
    safety_backup = create_full_backup(
        db=db,
        app_root=app_root,
        password=safety_pwd,
        created_by=f"AUTO ({restored_by})",
        prefix="auto_pre_restore",
        observacao=f"Snapshot automático criado antes de restaurar backup de {manifest.get('created_at_br', '')}",
    )

    # Fecha sessão ORM aberta para evitar locks em SQLite/Postgres antes da transação limpa
    db.session.remove()

    target_tables = get_target_tables(db)
    tables_by_name = {t.name: t for t in target_tables}
    dialect_name = db.engine.dialect.name
    restored_counts: Dict[str, int] = {}

    with zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r") as zf:
        # 3. Transação atômica do banco de dados
        with db.engine.begin() as conn:
            if dialect_name == "sqlite":
                conn.execute(text("PRAGMA foreign_keys = OFF"))

            # 3a. Limpeza em ordem reversa de dependências
            for table in reversed(target_tables):
                self_fks = _find_self_fk_columns(table)
                for fk_col in self_fks:
                    conn.execute(
                        table.update().values({fk_col: None})
                    )
                conn.execute(table.delete())

            # 3b. Inserção em ordem topológica (Pais -> Filhos)
            for table in target_tables:
                tname = table.name
                arc_path = f"database/{tname}.jsonl"
                if arc_path not in zf.namelist():
                    restored_counts[tname] = 0
                    continue

                raw_lines = zf.read(arc_path).decode("utf-8").splitlines()
                if not raw_lines:
                    restored_counts[tname] = 0
                    continue

                valid_cols = {c.name: c for c in table.columns}
                self_fks = _find_self_fk_columns(table)
                pk_cols = [c.name for c in table.primary_key.columns]

                rows_to_insert: List[Dict[str, Any]] = []
                deferred_self_fks: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []

                for line in raw_lines:
                    if not line.strip():
                        continue
                    raw_obj = json.loads(line)
                    clean_row: Dict[str, Any] = {}
                    for col_name, col_obj in valid_cols.items():
                        if col_name in raw_obj:
                            clean_row[col_name] = _deserialize_value(
                                raw_obj[col_name], col_obj.type
                            )
                        elif col_obj.default is not None and col_obj.default.is_scalar:
                            clean_row[col_name] = col_obj.default.arg

                    if self_fks:
                        saved_fks = {}
                        for fk_col in self_fks:
                            if fk_col in clean_row and clean_row[fk_col] is not None:
                                saved_fks[fk_col] = clean_row[fk_col]
                                clean_row[fk_col] = None
                        if saved_fks and pk_cols:
                            pk_vals = {pk: clean_row[pk] for pk in pk_cols if pk in clean_row}
                            deferred_self_fks.append((pk_vals, saved_fks))

                    rows_to_insert.append(clean_row)

                # Inserção em lotes de 500 registros
                batch_size = 500
                for idx in range(0, len(rows_to_insert), batch_size):
                    conn.execute(table.insert(), rows_to_insert[idx : idx + batch_size])

                # Passo 2 para auto-FKs (ex.: organograma_node.parent_id)
                for pk_vals, fk_updates in deferred_self_fks:
                    stmt = table.update()
                    for pk_name, pk_val in pk_vals.items():
                        stmt = stmt.where(table.c[pk_name] == pk_val)
                    conn.execute(stmt.values(**fk_updates))

                restored_counts[tname] = len(rows_to_insert)

            # 3c. Reajuste automático das sequências de IDs
            _reset_sequences(conn, dialect_name, target_tables)

            if dialect_name == "sqlite":
                conn.execute(text("PRAGMA foreign_keys = ON"))

        # 4. Restauração atômica das mídias físicas
        media_restored = _restore_media_files_atomic(app_root, zf, manifest)

    # 5. Hook opcional pós-restauração (ex.: backfill automático de colunas novas ao restaurar backup antigo)
    if callable(post_restore_hook):
        post_restore_hook()

    return {
        "restored_records": sum(restored_counts.values()),
        "restored_tables": restored_counts,
        "restored_media_files": media_restored,
        "backup_created_at": manifest.get("created_at_br"),
        "safety_backup": safety_backup,
    }
