"""
Serviço da Fase 4 — Fichas Profissionais 2.0, Dossiê Digital (GED) e Virada de Exercício 2027
=============================================================================================
Fornece:
- Validação matemática real de CPF (módulo 11)
- Validação segura de Foto 3x4 e upload de documentos GED (base64 persistente no DB -> 100% no Backup!)
- Checklist automático de documentos obrigatórios por servidor
- Motor de Simulação e Execução da Virada de Exercício (2026 -> 2027) em lote com preservação de histórico
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

import security

GED_TIPOS_DOCUMENTO: List[Tuple[str, str, bool]] = [
    # (codigo, rotulo, obrigatorio_padrao)
    ("RG", "RG / Documento de Identidade", True),
    ("CPF", "CPF / Comprovante de Situação Cadastral", True),
    ("TITULO_ELEITOR", "Título de Eleitor / Quitação Eleitoral", True),
    ("COMPROVANTE_RESIDENCIA", "Comprovante de Residência", True),
    ("DADOS_BANCARIOS", "Comprovante de Conta Bancária", True),
    ("PIS_PASEP", "Cartão PIS / PASEP / NIS", False),
    ("DIPLOMA_CERTIFICADO", "Diploma / Certificado de Escolaridade", False),
    ("PORTARIA_DECRETO", "Portaria / Decreto de Nomeação", False),
    ("CONTRATO_ASSINADO", "Contrato Administrativo Assinado", False),
    ("DECLARACAO_BENS", "Declaração de Bens / Acúmulo de Cargos", False),
    ("CERTIDAO_NASC_CAS", "Certidão de Nascimento / Casamento", False),
    ("RESERVISTA", "Certificado de Reservista", False),
    ("OUTRO", "Outro Documento Complementar", False),
]

GED_LABELS = {cod: lbl for cod, lbl, _ in GED_TIPOS_DOCUMENTO}
GED_OBRIGATORIOS = [cod for cod, _, obg in GED_TIPOS_DOCUMENTO if obg]

ALLOWED_GED_MIMES = {
    "application/pdf",
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
}

MAX_GED_BYTES = 5 * 1024 * 1024  # 5 MB por documento
MAX_FOTO_3X4_BYTES = 1_500_000   # ~1.5 MB base64


def validar_cpf_matematico(cpf_raw: Optional[str]) -> Tuple[bool, str]:
    """Valida CPF usando o algoritmo oficial dos 2 dígitos verificadores."""
    digits = re.sub(r"\D", "", str(cpf_raw or ""))
    if len(digits) != 11:
        return False, "CPF deve conter 11 dígitos numéricos."
    if digits == digits[0] * 11:
        return False, "CPF inválido (todos os dígitos iguais)."

    soma1 = sum(int(digits[i]) * (10 - i) for i in range(9))
    dv1 = (soma1 * 10) % 11
    dv1 = 0 if dv1 == 10 else dv1
    if dv1 != int(digits[9]):
        return False, "CPF com dígito verificador inválido."

    soma2 = sum(int(digits[i]) * (11 - i) for i in range(10))
    dv2 = (soma2 * 10) % 11
    dv2 = 0 if dv2 == 10 else dv2
    if dv2 != int(digits[10]):
        return False, "CPF com dígito verificador inválido."

    return True, digits


def validar_foto_3x4_b64(raw_val: Optional[str]) -> Tuple[bool, Optional[str], str]:
    """Valida e higieniza uma imagem 3x4 enviada em data URL base64."""
    if not raw_val or not str(raw_val).strip():
        return True, None, ""
    val = str(raw_val).strip()
    if len(val) > MAX_FOTO_3X4_BYTES:
        return False, None, "A foto 3x4 excede o tamanho máximo permitido (1,5 MB)."
    m = re.match(r"^data:(image/(?:jpeg|jpg|png|webp));base64,([A-Za-z0-9+/=\s]+)$", val)
    if not m:
        return False, None, "Formato de foto 3x4 inválido (use JPG, PNG ou WebP)."
    try:
        raw_bytes = base64.b64decode(m.group(2), validate=True)
        if len(raw_bytes) < 50:
            return False, None, "Arquivo de imagem 3x4 inválido ou vazio."
    except Exception:
        return False, None, "Conteúdo base64 da foto 3x4 corrompido."
    return True, f"data:{m.group(1)};base64,{re.sub(r'\s+', '', m.group(2))}", ""


def preparar_upload_ged(file_storage, tipo_documento: str) -> Tuple[bool, Dict[str, Any], str]:
    """Valida upload de documento para o GED e retorna metadados prontos para persistência."""
    tipo = (tipo_documento or "").strip().upper()
    if tipo not in GED_LABELS:
        return False, {}, "Tipo de documento inválido."

    if not file_storage or not file_storage.filename:
        return False, {}, "Selecione um arquivo para anexar."

    nome_orig = os.path.basename(file_storage.filename).strip()[:190]
    nome_seguro = re.sub(r"[^A-Za-z0-9._\-\sÀ-ÿ()]", "_", nome_orig) or "documento.pdf"
    ext = os.path.splitext(nome_seguro)[1].lower()

    mime = (file_storage.mimetype or "").lower().strip()
    if mime not in ALLOWED_GED_MIMES:
        # Fallback seguro por extensão
        ext_map = {
            ".pdf": "application/pdf",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".webp": "image/webp",
        }
        mime = ext_map.get(ext, "")
    if mime not in ALLOWED_GED_MIMES:
        return False, {}, "Formato não permitido. Envie apenas PDF, JPG, PNG ou WebP."

    raw_bytes = file_storage.read()
    if not raw_bytes:
        return False, {}, "O arquivo enviado está vazio."
    if len(raw_bytes) > MAX_GED_BYTES:
        return False, {}, "Arquivo muito grande (máximo 5 MB por documento)."

    sha = hashlib.sha256(raw_bytes).hexdigest()
    b64 = base64.b64encode(raw_bytes).decode("ascii")

    return True, {
        "tipo_documento": tipo,
        "nome_arquivo": nome_seguro,
        "mime_type": mime,
        "tamanho_bytes": len(raw_bytes),
        "sha256": sha,
        "conteudo_b64": b64,
    }, ""


def get_ged_checklist(documentos: List[Any]) -> Dict[str, Any]:
    """Monta o checklist de documentos obrigatórios e complementares do servidor."""
    by_tipo: Dict[str, List[Any]] = {}
    for doc in documentos or []:
        by_tipo.setdefault(doc.tipo_documento, []).append(doc)

    itens = []
    entregues_obg = 0
    validados_obg = 0
    for cod, lbl, obrigatorio in GED_TIPOS_DOCUMENTO:
        docs_tipo = by_tipo.get(cod, [])
        tem = len(docs_tipo) > 0
        algum_val = any(bool(d.validado) for d in docs_tipo)
        if obrigatorio:
            if tem:
                entregues_obg += 1
            if algum_val:
                validados_obg += 1
        itens.append(
            {
                "codigo": cod,
                "label": lbl,
                "obrigatorio": obrigatorio,
                "entregue": tem,
                "validado": algum_val,
                "qtd": len(docs_tipo),
            }
        )

    total_obg = len(GED_OBRIGATORIOS)
    pct_entregue = int(round((entregues_obg / total_obg) * 100)) if total_obg else 100
    return {
        "itens": itens,
        "total_documentos": len(documentos or []),
        "total_obrigatorios": total_obg,
        "entregues_obrigatorios": entregues_obg,
        "validados_obrigatorios": validados_obg,
        "pct_obrigatorios": pct_entregue,
    }


def formatar_brl_simples(valor: float) -> str:
    s = f"{float(valor or 0.0):,.2f}"
    return s.replace(",", "X").replace(".", ",").replace("X", ".")


def calcular_novo_salario(atual: float, tipo_reajuste: str, valor_reajuste: float) -> float:
    atual = float(atual or 0.0)
    if atual <= 0 or not valor_reajuste:
        return round(atual, 2)
    if tipo_reajuste == "percentual":
        return round(atual * (1.0 + (float(valor_reajuste) / 100.0)), 2)
    if tipo_reajuste == "fixo":
        return round(max(0.0, atual + float(valor_reajuste)), 2)
    return round(atual, 2)


def executar_virada_exercicio(
    db,
    models: Dict[str, Any],
    user,
    func_ids: List[int],
    ano_destino: int,
    nova_dt_inicio: date,
    nova_dt_termino: Optional[date],
    tipo_reajuste: str = "nenhum",  # 'nenhum' | 'percentual' | 'fixo'
    valor_reajuste: float = 0.0,
    numero_portaria: str = "",
    data_portaria: Optional[date] = None,
    observacao: str = "",
) -> Dict[str, Any]:
    """
    Executa a Virada de Exercício (ex.: 2026 -> 2027) em lote de forma atômica:
    1. Garante isolamento multi-secretarias (can_access_record) em cada servidor.
    2. Arquiva o vínculo do exercício anterior em HistoricoVinculoExercicio (sem duplicar).
    3. Grava o novo registro do ano_destino em HistoricoVinculoExercicio (status=ATIVO).
    4. Atualiza Funcionario (ano_exercicio_atual, dt_inicio, dt_termino, remuneração, portaria).
    """
    Funcionario = models["Funcionario"]
    HistoricoVinculoExercicio = models["HistoricoVinculoExercicio"]

    renovados = 0
    ignorados_acesso = 0
    folha_antes = 0.0
    folha_depois = 0.0
    nomes_renovados: List[str] = []

    for fid in func_ids:
        f = db.session.get(Funcionario, int(fid))
        if not f or f.ativo is False:
            continue
        if not security.can_access_record(user, f):
            ignorados_acesso += 1
            continue

        ano_anterior = int(f.ano_exercicio_atual or (f.dt_inicio.year if f.dt_inicio else (ano_destino - 1)))
        sal_atual = float(f.remuneracao_valor or 0.0)
        if sal_atual <= 0 and f.remuneracao:
            sal_atual = float(security.parse_remuneracao_float(f.remuneracao))
        grat_atual = float(getattr(f, "gratificacao_valor", 0.0) or 0.0)

        # 1. Arquiva snapshot do exercício anterior se ainda não existir histórico daquele ano
        if ano_anterior < ano_destino:
            ja_arquivado = HistoricoVinculoExercicio.query.filter_by(
                funcionario_id=f.id, ano_exercicio=ano_anterior
            ).first()
            if not ja_arquivado:
                snap_ant = HistoricoVinculoExercicio(
                    funcionario_id=f.id,
                    secretaria_id=f.secretaria_id,
                    ano_exercicio=ano_anterior,
                    funcao_nome=f.funcao.nome if f.funcao else "N/A",
                    local_trabalho_nome=f.local_trabalho.nome if f.local_trabalho else (f.lotacao or "N/A"),
                    tipo_vinculo=f.tipo_vinculo,
                    jornada_trabalho=f.jornada_trabalho,
                    remuneracao=f.remuneracao or formatar_brl_simples(sal_atual),
                    remuneracao_valor=sal_atual,
                    gratificacao_valor=grat_atual,
                    dt_inicio=f.dt_inicio,
                    dt_termino=f.dt_termino,
                    numero_portaria=f.numero_portaria,
                    data_portaria=f.data_portaria,
                    status="ENCERRADO",
                    observacao=f"Arquivado automaticamente na virada para {ano_destino}",
                    criado_por_id=user.id,
                )
                db.session.add(snap_ant)
            else:
                ja_arquivado.status = "ENCERRADO"

        # 2. Calcula nova remuneração
        sal_novo = calcular_novo_salario(sal_atual, tipo_reajuste, valor_reajuste)
        rem_str_nova = formatar_brl_simples(sal_novo) if sal_novo > 0 else (f.remuneracao or "")

        folha_antes += sal_atual
        folha_depois += sal_novo

        # 3. Atualiza ou cria o registro do ano_destino em HistoricoVinculoExercicio
        reg_dest = HistoricoVinculoExercicio.query.filter_by(
            funcionario_id=f.id, ano_exercicio=ano_destino
        ).first()
        if not reg_dest:
            reg_dest = HistoricoVinculoExercicio(
                funcionario_id=f.id,
                secretaria_id=f.secretaria_id,
                ano_exercicio=ano_destino,
                criado_por_id=user.id,
            )
            db.session.add(reg_dest)

        reg_dest.funcao_nome = f.funcao.nome if f.funcao else "N/A"
        reg_dest.local_trabalho_nome = f.local_trabalho.nome if f.local_trabalho else (f.lotacao or "N/A")
        reg_dest.tipo_vinculo = f.tipo_vinculo
        reg_dest.jornada_trabalho = f.jornada_trabalho
        reg_dest.remuneracao = rem_str_nova
        reg_dest.remuneracao_valor = sal_novo
        reg_dest.gratificacao_valor = grat_atual
        reg_dest.dt_inicio = nova_dt_inicio
        reg_dest.dt_termino = nova_dt_termino
        reg_dest.numero_portaria = numero_portaria or f.numero_portaria
        reg_dest.data_portaria = data_portaria or f.data_portaria
        reg_dest.status = "ATIVO"
        reg_dest.observacao = observacao or f"Renovação em lote para o exercício {ano_destino}"

        # 4. Atualiza ficha vigente do servidor
        f.ano_exercicio_atual = ano_destino
        f.dt_inicio = nova_dt_inicio
        f.dt_termino = nova_dt_termino
        if sal_novo > 0:
            f.remuneracao = rem_str_nova
            f.remuneracao_valor = sal_novo
        if numero_portaria:
            f.numero_portaria = numero_portaria
        if data_portaria:
            f.data_portaria = data_portaria

        renovados += 1
        nomes_renovados.append(f.nome)

    db.session.commit()
    return {
        "renovados": renovados,
        "ignorados_acesso": ignorados_acesso,
        "folha_antes": round(folha_antes, 2),
        "folha_depois": round(folha_depois, 2),
        "delta_mensal": round(folha_depois - folha_antes, 2),
        "nomes": nomes_renovados,
    }
