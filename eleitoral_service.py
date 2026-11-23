"""
Motor Analítico da Central Estratégica de Campanhas Eleitorais v2 (Gestoor 360)
================================================================================
Módulo 100% sigiloso restrito a `super_admin`, `prefeito` e `estrategia_eleitoral`.
Fornece:
- Matriz de Cobertura Colégio × Seção (identificando Seções Descobertas = 0 servidores)
- Dados geográficos para Mapa de Calor Interativo (Leaflet.js + OpenStreetMap)
- Painel de Desempenho por Liderança / Padrinho v2 (categoria, região, meta, colégios)
- Operação Regularização Eleitoral 2027 (ranking de metas por secretaria + lista nominal)
- Caderno de Campo por Colégio/Seção e Dossiê Estratégico por Liderança
- Exportação Excel Estratégica Multi-Abas (respeitando sigilo salarial para `estrategia_eleitoral`)
"""

from __future__ import annotations

import io
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pytz

import prefeito_service
import security

FUSO_BR = pytz.timezone("America/Sao_Paulo")

CATEGORIAS_LIDERANCA = [
    ("VEREADOR", "Vereador(a)"),
    ("EX_VEREADOR", "Ex-Vereador(a)"),
    ("SECRETARIO", "Secretário(a) Municipal"),
    ("LIDERANCA_COMUNITARIA", "Liderança Comunitária"),
    ("GABINETE", "Gabinete / Coordenação"),
    ("TECNICO", "Indicação Técnica"),
    ("LIDERANCA", "Liderança Política"),
    ("OUTRO", "Outro"),
]
CATEGORIA_LABELS = dict(CATEGORIAS_LIDERANCA)


def _now_br_fmt() -> str:
    return datetime.now(FUSO_BR).strftime("%d/%m/%Y às %H:%M")


def _format_brl(valor: float) -> str:
    s = f"{float(valor or 0.0):,.2f}"
    return "R$ " + s.replace(",", "X").replace(".", ",").replace("X", ".")


def _is_zona_valenca(zona_norm: str) -> bool:
    return bool(zona_norm and zona_norm in ("18", "018"))


def build_central_estrategica_data(
    models: Dict[str, Any],
    user,
    filtro_secretaria_id: Optional[int] = None,
    filtro_escopo: str = "todos",  # 'todos' | 'comissionados_contratados' | 'comissionado' | 'contratado' | 'efetivo'
    filtro_tipo_zona: str = "",  # '' | 'URBANA' | 'RURAL'
    filtro_padrinho_id: Optional[int] = None,
    filtro_busca: str = "",
) -> Dict[str, Any]:
    Secretaria = models["Secretaria"]
    Funcionario = models["Funcionario"]
    LocalVotacao = models["LocalVotacao"]
    Padrinho = models["Padrinho"]
    normalizar = models["normalizar_numero_eleitoral"]

    pode_ver_folha = security.has_permission(user, "view_folha")

    secretarias = Secretaria.query.order_by(Secretaria.nome).all()
    padrinhos = Padrinho.query.order_by(Padrinho.nome).all()
    locais_todos = LocalVotacao.query.order_by(LocalVotacao.nome).all()

    q_func = Funcionario.query.filter(
        (Funcionario.ativo == True) | (Funcionario.ativo.is_(None))
    )
    if filtro_secretaria_id:
        q_func = q_func.filter(Funcionario.secretaria_id == filtro_secretaria_id)
    if filtro_padrinho_id:
        q_func = q_func.filter(Funcionario.padrinho_id == filtro_padrinho_id)

    servidores_base = q_func.order_by(Funcionario.nome).all()

    # Aplica filtro de vínculo (foco em comissionados/contratados ou geral)
    def _match_escopo(f) -> bool:
        cat = prefeito_service.classify_vinculo(f.tipo_vinculo)
        if filtro_escopo == "comissionados_contratados":
            return cat in ("COMISSIONADO", "CONTRATADO")
        if filtro_escopo == "comissionado":
            return cat == "COMISSIONADO"
        if filtro_escopo == "contratado":
            return cat == "CONTRATADO"
        if filtro_escopo == "efetivo":
            return cat == "EFETIVO"
        return True

    funcionarios = [f for f in servidores_base if _match_escopo(f)]

    # Mapeia cada servidor para seu Colégio Eleitoral (se houver correspondência de Zona + Seção)
    sec_to_local: Dict[Tuple[str, str], Any] = {}
    secao_only_to_local: Dict[str, Any] = {}
    for loc in locais_todos:
        z_norm = normalizar(loc.zona_eleitoral) or "18"
        for s_raw in loc.get_secoes_list():
            s_norm = normalizar(s_raw)
            if s_norm:
                sec_to_local[(z_norm, s_norm)] = loc
                secao_only_to_local.setdefault(s_norm, loc)

    busca_low = (filtro_busca or "").strip().lower()

    # Agrupamento por Colégio e por Seção
    local_funcs: Dict[int, List[Any]] = defaultdict(list)
    local_secao_counts: Dict[int, Dict[str, List[Any]]] = defaultdict(lambda: defaultdict(list))
    mapeados_ids = set()
    pendentes_lista = []

    # Agregação por Secretaria para Operação Regularização 2027
    reg_por_sec: Dict[int, Dict[str, Any]] = {}
    for s in secretarias:
        reg_por_sec[s.id] = {
            "id": s.id,
            "nome": s.nome,
            "sigla": s.sigla or s.nome[:12],
            "total": 0,
            "mapeados": 0,
            "pendentes": 0,
            "sem_titulo": 0,
            "fora_zona18": 0,
        }

    # Agregação por Bairro / Povoado de Moradia
    por_bairro: Dict[str, Dict[str, Any]] = {}

    for f in funcionarios:
        f_zona_norm = normalizar(f.zona_eleitoral)
        f_sec_norm = normalizar(f.secao_eleitoral)
        sem_titulo = not (f.titulo_eleitor or "").strip()
        sem_zona = not f_zona_norm
        sem_secao = not f_sec_norm
        fora_z18 = bool(f_zona_norm and not _is_zona_valenca(f_zona_norm))

        matched_loc = None
        if f_sec_norm and not fora_z18:
            z_key = f_zona_norm or "18"
            matched_loc = sec_to_local.get((z_key, f_sec_norm)) or secao_only_to_local.get(f_sec_norm)

        if matched_loc:
            mapeados_ids.add(f.id)
            local_funcs[matched_loc.id].append(f)
            local_secao_counts[matched_loc.id][f_sec_norm].append(f)

        # Estatísticas de Regularização 2027 por secretaria
        if f.secretaria_id in reg_por_sec:
            rs = reg_por_sec[f.secretaria_id]
            rs["total"] += 1
            if matched_loc:
                rs["mapeados"] += 1
            else:
                rs["pendentes"] += 1
            if sem_titulo:
                rs["sem_titulo"] += 1
            if fora_z18:
                rs["fora_zona18"] += 1

        # Pendências nominais (Operação Regularização 2027)
        if not matched_loc or sem_titulo or fora_z18 or sem_zona or sem_secao:
            motivos = []
            if sem_titulo:
                motivos.append("Sem Título")
            if sem_zona:
                motivos.append("Sem Zona")
            elif fora_z18:
                motivos.append(f"Zona {f.zona_eleitoral} (Fora da 018)")
            if sem_secao:
                motivos.append("Sem Seção")
            elif not matched_loc:
                motivos.append("Seção não vinculada a colégio")

            pendentes_lista.append(
                {
                    "id": f.id,
                    "nome": f.nome,
                    "cpf": f.cpf or "---",
                    "telefone": f.telefone or "---",
                    "secretaria": (f.secretaria.sigla or f.secretaria.nome) if f.secretaria else "---",
                    "funcao": f.funcao.nome if f.funcao else "---",
                    "tipo_vinculo": f.tipo_vinculo or "---",
                    "titulo": f.titulo_eleitor or "---",
                    "zona": f.zona_eleitoral or "---",
                    "secao": f.secao_eleitoral or "---",
                    "padrinho": f.padrinho.nome if f.padrinho else "---",
                    "motivo": " • ".join(motivos),
                }
            )

        # Distribuição por Bairro / Povoado
        zona_m = (getattr(f, "zona_moradia", None) or "URBANA").upper()
        local_moradia = (getattr(f, "povoado_comunidade", None) or f.bairro or "NÃO INFORMADO").strip().upper()
        chave_b = f"{local_moradia} ({'RURAL' if zona_m == 'RURAL' else 'URBANA'})"
        if chave_b not in por_bairro:
            por_bairro[chave_b] = {
                "nome": local_moradia,
                "zona": "RURAL" if zona_m == "RURAL" else "URBANA",
                "total": 0,
                "com_e_cont": 0,
                "mapeados": 0,
            }
        por_bairro[chave_b]["total"] += 1
        if prefeito_service.is_comissionado_ou_contratado(f.tipo_vinculo):
            por_bairro[chave_b]["com_e_cont"] += 1
        if matched_loc:
            por_bairro[chave_b]["mapeados"] += 1

    # Monta Matriz de Cobertura por Colégio e Seções Descobertas
    matriz_colegios = []
    mapa_pontos = []
    secoes_descobertas_lista = []
    total_secoes_cadastradas = 0
    total_secoes_cobertas = 0

    for loc in locais_todos:
        tz = (getattr(loc, "tipo_zona", None) or "URBANA").upper()
        if filtro_tipo_zona and tz != filtro_tipo_zona:
            continue
        if busca_low and busca_low not in loc.nome.lower() and busca_low not in (loc.bairro or "").lower() and busca_low not in (loc.secoes or "").lower():
            continue

        funcs_loc = local_funcs.get(loc.id, [])
        com_cont_loc = sum(1 for x in funcs_loc if prefeito_service.is_comissionado_ou_contratado(x.tipo_vinculo))
        efet_loc = sum(1 for x in funcs_loc if prefeito_service.classify_vinculo(x.tipo_vinculo) == "EFETIVO")
        liderancas_loc = sorted({x.padrinho.nome for x in funcs_loc if x.padrinho})

        secoes_detalhe = []
        secoes_zero_neste = []
        for s_raw in loc.get_secoes_list():
            s_norm = normalizar(s_raw)
            if not s_norm:
                continue
            total_secoes_cadastradas += 1
            qtd_s = len(local_secao_counts[loc.id].get(s_norm, []))
            if qtd_s > 0:
                total_secoes_cobertas += 1
            else:
                secoes_zero_neste.append(s_raw)
                secoes_descobertas_lista.append(
                    {
                        "local_id": loc.id,
                        "colegio": loc.nome,
                        "bairro": loc.bairro or "---",
                        "tipo_zona": tz,
                        "zona": loc.zona_eleitoral,
                        "secao": s_raw,
                    }
                )
            secoes_detalhe.append({"secao": s_raw, "qtd": qtd_s})

        qtd_secoes_loc = len(secoes_detalhe)
        cobertas_loc = sum(1 for sd in secoes_detalhe if sd["qtd"] > 0)
        pct_cob_loc = round((cobertas_loc / qtd_secoes_loc) * 100.0, 1) if qtd_secoes_loc else 0.0
        meta_loc = int(getattr(loc, "meta_cobertura", 0) or 0)
        total_loc = len(funcs_loc)

        # Nível de calor / prioridade territorial
        if total_loc == 0:
            nivel = "CRITICO"  # Zona silenciosa!
        elif (meta_loc > 0 and total_loc >= meta_loc) or (total_loc >= 10 and pct_cob_loc >= 70):
            nivel = "FORTE"
        else:
            nivel = "MODERADO"

        item_col = {
            "id": loc.id,
            "nome": loc.nome,
            "zona_eleitoral": loc.zona_eleitoral,
            "tipo_zona": tz,
            "bairro": loc.bairro or "---",
            "endereco": loc.endereco or "---",
            "latitude": loc.latitude,
            "longitude": loc.longitude,
            "meta_cobertura": meta_loc,
            "total_servidores": total_loc,
            "com_e_cont": com_cont_loc,
            "efetivos": efet_loc,
            "qtd_secoes": qtd_secoes_loc,
            "secoes_cobertas": cobertas_loc,
            "secoes_descobertas": len(secoes_zero_neste),
            "pct_cobertura": pct_cob_loc,
            "secoes_detalhe": secoes_detalhe,
            "liderancas": liderancas_loc,
            "nivel": nivel,
        }
        matriz_colegios.append(item_col)

        if loc.latitude is not None and loc.longitude is not None:
            mapa_pontos.append(
                {
                    "id": loc.id,
                    "nome": loc.nome,
                    "bairro": loc.bairro or "---",
                    "tipo_zona": tz,
                    "lat": float(loc.latitude),
                    "lng": float(loc.longitude),
                    "total": total_loc,
                    "com_e_cont": com_cont_loc,
                    "cobertura_pct": pct_cob_loc,
                    "descobertas": len(secoes_zero_neste),
                    "nivel": nivel,
                }
            )

    matriz_colegios.sort(key=lambda x: (x["total_servidores"], x["pct_cobertura"]), reverse=True)

    # Painel de Lideranças / Padrinhos v2
    liderancas_ranking = []
    funcs_by_pad: Dict[int, List[Any]] = defaultdict(list)
    for f in funcionarios:
        if f.padrinho_id:
            funcs_by_pad[f.padrinho_id].append(f)

    for p in padrinhos:
        indicados = funcs_by_pad.get(p.id, [])
        tot_ind = len(indicados)
        com_ind = sum(1 for x in indicados if prefeito_service.is_comissionado_ou_contratado(x.tipo_vinculo))
        reg_ind = sum(1 for x in indicados if x.id in mapeados_ids)
        pct_reg_ind = round((reg_ind / tot_ind) * 100.0, 1) if tot_ind else 0.0
        meta_b = int(getattr(p, "meta_base", 0) or 0)
        pct_meta = round((tot_ind / meta_b) * 100.0, 1) if meta_b > 0 else 0.0

        # Top colégios onde os indicados desta liderança votam
        col_count: Dict[str, int] = defaultdict(int)
        secs_set = set()
        folha_pad = 0.0
        for x in indicados:
            if x.secretaria:
                secs_set.add(x.secretaria.sigla or x.secretaria.nome[:12])
            if pode_ver_folha:
                folha_pad += prefeito_service.get_salario_valor(x)
            xz = normalizar(x.zona_eleitoral) or "18"
            xs = normalizar(x.secao_eleitoral)
            if xs and _is_zona_valenca(xz):
                ml = sec_to_local.get((xz, xs)) or secao_only_to_local.get(xs)
                if ml:
                    col_count[ml.nome] += 1

        top_cols = sorted(col_count.items(), key=lambda kv: kv[1], reverse=True)[:3]
        cat_code = (getattr(p, "categoria", None) or "LIDERANCA").upper()

        liderancas_ranking.append(
            {
                "id": p.id,
                "nome": p.nome,
                "categoria": cat_code,
                "categoria_label": CATEGORIA_LABELS.get(cat_code, cat_code),
                "regiao_atuacao": getattr(p, "regiao_atuacao", None) or "",
                "telefone": getattr(p, "telefone", None) or "",
                "meta_base": meta_b,
                "pct_meta": pct_meta,
                "observacoes": getattr(p, "observacoes", None) or "",
                "ativo": bool(True if getattr(p, "ativo", True) is None else getattr(p, "ativo", True)),
                "total_indicados": tot_ind,
                "com_e_cont": com_ind,
                "regularizados_z18": reg_ind,
                "pct_regularizados": pct_reg_ind,
                "secretarias": sorted(secs_set),
                "top_colegios": [{"nome": n, "qtd": q} for n, q in top_cols],
                "folha_mensal": folha_pad if pode_ver_folha else None,
                "folha_mensal_fmt": _format_brl(folha_pad) if pode_ver_folha else None,
            }
        )
    liderancas_ranking.sort(key=lambda x: (x["total_indicados"], x["meta_base"]), reverse=True)

    # Regularização 2027 por Secretaria
    regularizacao_secretarias = []
    for rs in reg_por_sec.values():
        if rs["total"] == 0:
            continue
        rs["pct_regular"] = round((rs["mapeados"] / rs["total"]) * 100.0, 1)
        regularizacao_secretarias.append(rs)
    regularizacao_secretarias.sort(key=lambda x: x["pct_regular"])

    bairros_ranking = sorted(por_bairro.values(), key=lambda x: x["total"], reverse=True)

    total_base = len(funcionarios)
    total_map = len(mapeados_ids)
    total_cc = sum(1 for f in funcionarios if prefeito_service.is_comissionado_ou_contratado(f.tipo_vinculo))
    pct_secoes_cob = round((total_secoes_cobertas / total_secoes_cadastradas) * 100.0, 1) if total_secoes_cadastradas else 0.0

    return {
        "gerado_em_fmt": _now_br_fmt(),
        "pode_ver_folha": pode_ver_folha,
        "categorias_lideranca": CATEGORIAS_LIDERANCA,
        "kpis": {
            "total_base": total_base,
            "total_com_e_cont": total_cc,
            "total_mapeados": total_map,
            "pct_mapeados": round((total_map / total_base) * 100.0, 1) if total_base else 0.0,
            "total_pendentes": len(pendentes_lista),
            "total_colegios": len(matriz_colegios),
            "colegios_silenciosos": sum(1 for c in matriz_colegios if c["total_servidores"] == 0),
            "colegios_georreferenciados": len(mapa_pontos),
            "total_secoes": total_secoes_cadastradas,
            "secoes_cobertas": total_secoes_cobertas,
            "secoes_descobertas": len(secoes_descobertas_lista),
            "pct_secoes_cobertas": pct_secoes_cob,
            "total_liderancas": len(liderancas_ranking),
        },
        "matriz_colegios": matriz_colegios,
        "mapa_pontos": mapa_pontos,
        "secoes_descobertas": secoes_descobertas_lista,
        "liderancas_ranking": liderancas_ranking,
        "regularizacao_secretarias": regularizacao_secretarias,
        "pendentes_lista": pendentes_lista,
        "bairros_ranking": bairros_ranking,
        "secretarias": secretarias,
        "padrinhos": padrinhos,
        "filtros": {
            "secretaria_id": filtro_secretaria_id,
            "escopo": filtro_escopo,
            "tipo_zona": filtro_tipo_zona,
            "padrinho_id": filtro_padrinho_id,
            "busca": filtro_busca,
        },
    }


def build_caderno_campo_data(
    models: Dict[str, Any],
    local_id: Optional[int] = None,
    secretaria_id: Optional[int] = None,
    escopo: str = "todos",
) -> Dict[str, Any]:
    """Monta dados estruturados do Caderno de Campo por Colégio Eleitoral -> Seção."""
    LocalVotacao = models["LocalVotacao"]
    Funcionario = models["Funcionario"]
    normalizar = models["normalizar_numero_eleitoral"]

    q_loc = LocalVotacao.query
    if local_id:
        q_loc = q_loc.filter_by(id=local_id)
    locais = q_loc.order_by(LocalVotacao.nome).all()

    q_func = Funcionario.query.filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None)))
    if secretaria_id:
        q_func = q_func.filter_by(secretaria_id=secretaria_id)
    funcs = q_func.order_by(Funcionario.nome).all()
    if escopo == "comissionados_contratados":
        funcs = [f for f in funcs if prefeito_service.is_comissionado_ou_contratado(f.tipo_vinculo)]

    blocos = []
    total_geral = 0
    for loc in locais:
        z_loc = normalizar(loc.zona_eleitoral) or "18"
        secoes_raw = loc.get_secoes_list()
        secoes_map = {normalizar(s): [] for s in secoes_raw if normalizar(s)}

        for f in funcs:
            fz = normalizar(f.zona_eleitoral)
            fs = normalizar(f.secao_eleitoral)
            if (not fz or fz in ("18", "018", z_loc)) and fs in secoes_map:
                secoes_map[fs].append(f)

        secoes_blocos = []
        tot_loc = 0
        for s_raw in secoes_raw:
            sn = normalizar(s_raw)
            if not sn:
                continue
            lista_s = sorted(secoes_map.get(sn, []), key=lambda x: x.nome)
            tot_loc += len(lista_s)
            secoes_blocos.append({"secao": s_raw, "servidores": lista_s})

        total_geral += tot_loc
        blocos.append(
            {
                "local": loc,
                "total": tot_loc,
                "secoes": secoes_blocos,
            }
        )

    return {
        "gerado_em_fmt": _now_br_fmt(),
        "total_geral": total_geral,
        "escopo": escopo,
        "blocos": blocos,
    }


def build_dossie_lideranca_data(
    models: Dict[str, Any],
    padrinho_id: int,
    pode_ver_folha: bool = False,
) -> Optional[Dict[str, Any]]:
    Padrinho = models["Padrinho"]
    Funcionario = models["Funcionario"]
    LocalVotacao = models["LocalVotacao"]
    normalizar = models["normalizar_numero_eleitoral"]

    pad = Padrinho.query.get(padrinho_id)
    if not pad:
        return None

    indicados = (
        Funcionario.query.filter(
            Funcionario.padrinho_id == pad.id,
            (Funcionario.ativo == True) | (Funcionario.ativo.is_(None)),
        )
        .order_by(Funcionario.nome)
        .all()
    )
    locais = LocalVotacao.query.all()
    sec_to_loc = {}
    for loc in locais:
        for s_raw in loc.get_secoes_list():
            sn = normalizar(s_raw)
            if sn:
                sec_to_loc.setdefault(sn, loc)

    por_colegio: Dict[str, int] = defaultdict(int)
    por_secretaria: Dict[str, int] = defaultdict(int)
    pendentes = []
    folha_total = 0.0
    linhas = []

    for f in indicados:
        snome = f.secretaria.nome if f.secretaria else "Sem Secretaria"
        por_secretaria[snome] += 1
        fz = normalizar(f.zona_eleitoral)
        fs = normalizar(f.secao_eleitoral)
        loc = sec_to_loc.get(fs) if (fs and (not fz or _is_zona_valenca(fz))) else None
        col_nome = loc.nome if loc else "NÃO MAPEADO / FORA ZONA 18"
        por_colegio[col_nome] += 1
        if not loc:
            pendentes.append(f)
        sal = prefeito_service.get_salario_valor(f)
        if pode_ver_folha:
            folha_total += sal
        linhas.append(
            {
                "nome": f.nome,
                "telefone": f.telefone or "---",
                "secretaria": (f.secretaria.sigla or snome[:14]) if f.secretaria else "---",
                "funcao": f.funcao.nome if f.funcao else "---",
                "tipo_vinculo": f.tipo_vinculo or "---",
                "bairro": (getattr(f, "povoado_comunidade", None) or f.bairro or "---"),
                "zona": f.zona_eleitoral or "---",
                "secao": f.secao_eleitoral or "---",
                "colegio": col_nome,
                "remuneracao_fmt": _format_brl(sal) if pode_ver_folha else None,
            }
        )

    return {
        "gerado_em_fmt": _now_br_fmt(),
        "lideranca": pad,
        "categoria_label": CATEGORIA_LABELS.get((getattr(pad, "categoria", None) or "LIDERANCA").upper(), "Liderança"),
        "pode_ver_folha": pode_ver_folha,
        "total_indicados": len(indicados),
        "total_com_e_cont": sum(1 for x in indicados if prefeito_service.is_comissionado_ou_contratado(x.tipo_vinculo)),
        "total_regularizados": len(indicados) - len(pendentes),
        "total_pendentes": len(pendentes),
        "folha_total_fmt": _format_brl(folha_total) if pode_ver_folha else None,
        "por_colegio": sorted(por_colegio.items(), key=lambda x: x[1], reverse=True),
        "por_secretaria": sorted(por_secretaria.items(), key=lambda x: x[1], reverse=True),
        "linhas": linhas,
    }


def export_eleitoral_excel_bytes(dados: Dict[str, Any]) -> bytes:
    """Exporta Excel Estratégico Multi-Abas respeitando sigilo de salários conforme RBAC."""
    import pandas as pd

    pode_ver_folha = bool(dados.get("pode_ver_folha"))
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        # Aba 1: Matriz Colégios
        df_col = pd.DataFrame(
            [
                {
                    "Colégio Eleitoral": c["nome"],
                    "Zona": c["zona_eleitoral"],
                    "Urbana/Rural": c["tipo_zona"],
                    "Bairro": c["bairro"],
                    "Total Servidores": c["total_servidores"],
                    "Comiss. + Contrat.": c["com_e_cont"],
                    "Efetivos": c["efetivos"],
                    "Total Seções": c["qtd_secoes"],
                    "Seções Cobertas": c["secoes_cobertas"],
                    "Seções Descobertas": c["secoes_descobertas"],
                    "% Cobertura Seções": c["pct_cobertura"],
                    "Status": c["nivel"],
                    "Lideranças Presentes": ", ".join(c["liderancas"]),
                }
                for c in dados["matriz_colegios"]
            ]
            or [{"Info": "Sem colégios cadastrados."}]
        )
        df_col.to_excel(writer, sheet_name="Matriz Colegios", index=False)

        # Aba 2: Seções Descobertas
        df_desc = pd.DataFrame(
            [
                {
                    "Colégio Eleitoral": s["colegio"],
                    "Urbana/Rural": s["tipo_zona"],
                    "Bairro": s["bairro"],
                    "Zona": s["zona"],
                    "Seção Descoberta (0)": s["secao"],
                }
                for s in dados["secoes_descobertas"]
            ]
            or [{"Info": "Parabéns! Todas as seções possuem cobertura."}]
        )
        df_desc.to_excel(writer, sheet_name="Secoes Descobertas", index=False)

        # Aba 3: Ranking Lideranças
        lid_rows = []
        for p in dados["liderancas_ranking"]:
            row = {
                "Liderança / Padrinho": p["nome"],
                "Categoria": p["categoria_label"],
                "Região de Atuação": p["regiao_atuacao"],
                "Telefone": p["telefone"],
                "Meta de Base": p["meta_base"],
                "Total Indicados": p["total_indicados"],
                "Comiss. + Contrat.": p["com_e_cont"],
                "% Regularizados Z018": p["pct_regularizados"],
                "Secretarias": ", ".join(p["secretarias"]),
                "Top Colégios": ", ".join(f"{tc['nome']} ({tc['qtd']})" for tc in p["top_colegios"]),
            }
            if pode_ver_folha:
                row["Impacto Mensal Folha (R$)"] = round(float(p["folha_mensal"] or 0.0), 2)
            lid_rows.append(row)
        df_lid = pd.DataFrame(lid_rows or [{"Info": "Sem lideranças cadastradas."}])
        df_lid.to_excel(writer, sheet_name="Ranking Liderancas", index=False)

        # Aba 4: Operação Regularização 2027
        df_pend = pd.DataFrame(
            [
                {
                    "Servidor": p["nome"],
                    "CPF": p["cpf"],
                    "Telefone": p["telefone"],
                    "Secretaria": p["secretaria"],
                    "Vínculo": p["tipo_vinculo"],
                    "Título": p["titulo"],
                    "Zona": p["zona"],
                    "Seção": p["secao"],
                    "Padrinho": p["padrinho"],
                    "Motivo Pendência": p["motivo"],
                }
                for p in dados["pendentes_lista"]
            ]
            or [{"Info": "Nenhuma pendência eleitoral!"}]
        )
        df_pend.to_excel(writer, sheet_name="Regularizacao 2027", index=False)

    output.seek(0)
    return output.getvalue()
