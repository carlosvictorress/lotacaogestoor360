"""
Serviço Analítico Executivo — Painel Supremo do Prefeito (Gestoor 360 v2027)
===========================================================================
Consolida em tempo real os indicadores estratégicos de todas as secretarias:
- Foco em Comissionados & Contratados vs. quadro geral
- Termômetro de tetos (vagas e folha mensal) por secretaria
- Radar de vencimentos de contratos (15 / 30 / 60 / 90 dias + vencidos)
- Detector em tempo real de acúmulo de CPF entre secretarias
- Evolução mensal (12 meses) de admissões x rescisões
- Ranking de Lideranças / Padrinhos com impacto financeiro mensal
- Dossiê Raio-X 360° individual do servidor
- Exportação executiva multi-abas em Excel (.xlsx)
"""

from __future__ import annotations

import io
import re
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pytz
from sqlalchemy import func

import security

FUSO_BR = pytz.timezone("America/Sao_Paulo")


def _now_br() -> datetime:
    return datetime.now(FUSO_BR).replace(tzinfo=None)


def _today_br() -> date:
    return _now_br().date()


def classify_vinculo(tipo_vinculo: Optional[str]) -> str:
    """Normaliza o tipo de vínculo em categorias executivas padronizadas."""
    raw = (tipo_vinculo or "").strip().upper()
    if not raw:
        return "NAO_INFORMADO"
    if "COMISSION" in raw:
        return "COMISSIONADO"
    if "CONTRAT" in raw or "TEMPOR" in raw or "PRESTAD" in raw or "SELETIV" in raw:
        return "CONTRATADO"
    if "EFETIV" in raw or "CONCURS" in raw or "ESTATUT" in raw:
        return "EFETIVO"
    if "TERCEIR" in raw:
        return "TERCEIRIZADO"
    if "ESTAG" in raw:
        return "ESTAGIARIO"
    return "OUTRO"


def is_comissionado_ou_contratado(tipo_vinculo: Optional[str]) -> bool:
    return classify_vinculo(tipo_vinculo) in ("COMISSIONADO", "CONTRATADO")


def get_salario_valor(func_obj) -> float:
    val = getattr(func_obj, "remuneracao_valor", None)
    if val is not None and float(val) > 0:
        return float(val)
    return float(security.parse_remuneracao_float(getattr(func_obj, "remuneracao", None)))


def get_cpf_digits(func_obj) -> str:
    c = getattr(func_obj, "cpf_limpo", None)
    if c:
        return re.sub(r"\D", "", str(c))
    return re.sub(r"\D", "", str(getattr(func_obj, "cpf", None) or ""))


def calc_completude_servidor(f) -> Tuple[int, List[str]]:
    """Calcula percentual de preenchimento cadastral (0-100%) e lista pendências."""
    checks = [
        ("CPF", bool(get_cpf_digits(f))),
        ("RG", bool((f.rg or "").strip())),
        ("Data de Nascimento", bool(f.data_nasc)),
        ("Telefone", bool((f.telefone or "").strip())),
        ("Endereço", bool((f.endereco or "").strip())),
        ("Escolaridade", bool((f.escolaridade or "").strip())),
        ("Local de Trabalho", bool(f.local_trabalho_id)),
        ("Função/Cargo", bool(f.funcao_id)),
        ("Vínculo", bool((f.tipo_vinculo or "").strip())),
        ("Data de Início", bool(f.dt_inicio)),
        ("Remuneração", get_salario_valor(f) > 0),
        ("Dados Bancários", bool((f.banco or "").strip() and (f.conta or "").strip())),
        ("Título/Zona/Seção", bool((f.titulo_eleitor or "").strip() and (f.zona_eleitoral or "").strip() and (f.secao_eleitoral or "").strip())),
        ("Validação RH", bool(f.validado)),
    ]
    preenchidos = sum(1 for _, ok in checks if ok)
    faltantes = [label for label, ok in checks if not ok]
    pct = int(round((preenchidos / len(checks)) * 100))
    return pct, faltantes


def _semaforo_teto(atual: float, teto: float) -> Dict[str, Any]:
    if not teto or teto <= 0:
        return {"pct": 0.0, "status": "SEM_TETO", "label": "Sem teto"}
    pct = round((atual / teto) * 100.0, 1)
    if pct >= 100.0:
        return {"pct": pct, "status": "CRITICO", "label": "Acima do teto"}
    if pct >= 85.0:
        return {"pct": pct, "status": "ATENCAO", "label": "Próximo do limite"}
    return {"pct": pct, "status": "NORMAL", "label": "Dentro do teto"}


def _format_brl(valor: float) -> str:
    s = f"{float(valor or 0.0):,.2f}"
    return "R$ " + s.replace(",", "X").replace(".", ",").replace("X", ".")


def build_prefeito_dashboard_data(
    models: Dict[str, Any],
    filtro_secretaria_id: Optional[int] = None,
    filtro_escopo: str = "comissionados_contratados",  # 'comissionados_contratados' | 'todos' | 'comissionado' | 'contratado' | 'efetivo' | 'terceirizado'
    filtro_padrinho_id: Optional[int] = None,
    filtro_validacao: str = "",  # '' | 'validado' | 'pendente'
    filtro_busca: str = "",
) -> Dict[str, Any]:
    """
    Constrói o snapshot executivo completo do Painel Supremo do Prefeito.
    """
    Secretaria = models["Secretaria"]
    Funcionario = models["Funcionario"]
    RescisaoHistorico = models["RescisaoHistorico"]
    ContratoGerado = models["ContratoGerado"]
    LogAuditoria = models["LogAuditoria"]
    BackupHistorico = models["BackupHistorico"]
    Padrinho = models["Padrinho"]
    LocalTrabalho = models["LocalTrabalho"]

    hoje = _today_br()

    # 1. Carrega secretarias, servidores ativos (base global) e listas de apoio
    secretarias = Secretaria.query.order_by(Secretaria.nome).all()
    sec_by_id = {s.id: s for s in secretarias}

    todos_ativos = (
        Funcionario.query.filter(
            (Funcionario.ativo == True) | (Funcionario.ativo.is_(None))
        )
        .order_by(Funcionario.nome)
        .all()
    )
    padrinhos_lista = Padrinho.query.order_by(Padrinho.nome).all()

    # 2. Aplica filtro de escopo para tabela/KPIs filtrados (mantendo também visão global intacta)
    busca_norm = (filtro_busca or "").strip().lower()
    busca_digits = re.sub(r"\D", "", busca_norm)

    def _matches_scope(f) -> bool:
        cat = classify_vinculo(f.tipo_vinculo)
        if filtro_escopo == "comissionados_contratados":
            return cat in ("COMISSIONADO", "CONTRATADO")
        if filtro_escopo == "comissionado":
            return cat == "COMISSIONADO"
        if filtro_escopo == "contratado":
            return cat == "CONTRATADO"
        if filtro_escopo == "efetivo":
            return cat == "EFETIVO"
        if filtro_escopo == "terceirizado":
            return cat == "TERCEIRIZADO"
        return True

    def _matches_filters(f) -> bool:
        if not _matches_scope(f):
            return False
        if filtro_secretaria_id and f.secretaria_id != filtro_secretaria_id:
            return False
        if filtro_padrinho_id and f.padrinho_id != filtro_padrinho_id:
            return False
        if filtro_validacao == "validado" and not f.validado:
            return False
        if filtro_validacao == "pendente" and f.validado:
            return False
        if busca_norm:
            nome_m = busca_norm in (f.nome or "").lower()
            func_m = busca_norm in ((f.funcao.nome if f.funcao else "") or "").lower()
            loc_m = busca_norm in ((f.local_trabalho.nome if f.local_trabalho else "") or "").lower()
            cpf_m = bool(busca_digits) and busca_digits in get_cpf_digits(f)
            if not (nome_m or func_m or loc_m or cpf_m):
                return False
        return True

    # 3. KPIs Globais (Município Inteiro) + Escopo Filtrado
    total_ativos_municipio = len(todos_ativos)
    total_comissionados_mun = 0
    total_contratados_mun = 0
    total_efetivos_mun = 0
    total_terceirizados_mun = 0
    total_outros_mun = 0

    folha_mensal_total = 0.0
    folha_mensal_com_cont = 0.0
    sem_remuneracao_com_cont = 0
    pendentes_validacao_total = 0
    pendentes_validacao_com_cont = 0
    eleitoral_regular_total = 0
    completude_soma = 0

    # Estruturas auxiliares por secretaria, CPF e padrinho
    sec_stats: Dict[int, Dict[str, Any]] = {}
    for s in secretarias:
        sec_stats[s.id] = {
            "id": s.id,
            "nome": s.nome,
            "sigla": s.sigla or s.nome[:12],
            "secretario_nome": s.secretario_nome or "Não configurado",
            "teto_comissionados": int(s.teto_comissionados or 0),
            "teto_folha_mensal": float(s.teto_folha_mensal or 0.0),
            "total_ativos": 0,
            "comissionados": 0,
            "contratados": 0,
            "com_e_cont": 0,
            "efetivos": 0,
            "terceirizados": 0,
            "pendentes": 0,
            "folha_mensal": 0.0,
            "folha_com_cont": 0.0,
            "contratos_vencendo_30": 0,
            "contratos_vencidos": 0,
        }

    cpf_groups: Dict[str, List[Any]] = defaultdict(list)
    padrinho_agg: Dict[int, Dict[str, Any]] = {}
    radar_vencimentos = {
        "vencidos": [],
        "d15": [],
        "d30": [],
        "d60": [],
        "d90": [],
        "sem_termino_com_cont": 0,
    }
    vinculos_dist: Dict[str, int] = defaultdict(int)
    servidores_filtrados = []

    for f in todos_ativos:
        cat = classify_vinculo(f.tipo_vinculo)
        sal = get_salario_valor(f)
        cpf_d = get_cpf_digits(f)
        pct_comp, _ = calc_completude_servidor(f)
        completude_soma += pct_comp

        vinculo_label = (f.tipo_vinculo or "Não Informado").strip()
        vinculos_dist[vinculo_label] += 1

        folha_mensal_total += sal
        if not f.validado:
            pendentes_validacao_total += 1
        if (f.titulo_eleitor or "").strip() and (f.zona_eleitoral or "").strip() and (f.secao_eleitoral or "").strip():
            eleitoral_regular_total += 1

        if cat == "COMISSIONADO":
            total_comissionados_mun += 1
        elif cat == "CONTRATADO":
            total_contratados_mun += 1
        elif cat == "EFETIVO":
            total_efetivos_mun += 1
        elif cat == "TERCEIRIZADO":
            total_terceirizados_mun += 1
        else:
            total_outros_mun += 1

        is_cc = cat in ("COMISSIONADO", "CONTRATADO")
        if is_cc:
            folha_mensal_com_cont += sal
            if sal <= 0:
                sem_remuneracao_com_cont += 1
            if not f.validado:
                pendentes_validacao_com_cont += 1

        # Acumula por secretaria
        if f.secretaria_id in sec_stats:
            st = sec_stats[f.secretaria_id]
            st["total_ativos"] += 1
            st["folha_mensal"] += sal
            if not f.validado:
                st["pendentes"] += 1
            if cat == "COMISSIONADO":
                st["comissionados"] += 1
                st["com_e_cont"] += 1
                st["folha_com_cont"] += sal
            elif cat == "CONTRATADO":
                st["contratados"] += 1
                st["com_e_cont"] += 1
                st["folha_com_cont"] += sal
            elif cat == "EFETIVO":
                st["efetivos"] += 1
            elif cat == "TERCEIRIZADO":
                st["terceirizados"] += 1

        # Agrupa CPFs válidos (11 dígitos) para detectar acúmulos
        if len(cpf_d) == 11:
            cpf_groups[cpf_d].append(f)

        # Radar de Vencimentos
        if f.dt_termino:
            dias_rest = (f.dt_termino - hoje).days
            item_v = {
                "id": f.id,
                "nome": f.nome,
                "cpf": f.cpf or "---",
                "secretaria": f.secretaria.sigla or f.secretaria.nome if f.secretaria else "---",
                "secretaria_id": f.secretaria_id,
                "funcao": f.funcao.nome if f.funcao else "Não Definida",
                "tipo_vinculo": f.tipo_vinculo or "---",
                "dt_termino_fmt": f.dt_termino.strftime("%d/%m/%Y"),
                "dias_restantes": dias_rest,
                "remuneracao_val": sal,
                "remuneracao_fmt": _format_brl(sal),
            }
            if dias_rest < 0:
                radar_vencimentos["vencidos"].append(item_v)
                if f.secretaria_id in sec_stats:
                    sec_stats[f.secretaria_id]["contratos_vencidos"] += 1
            elif dias_rest <= 15:
                radar_vencimentos["d15"].append(item_v)
                if f.secretaria_id in sec_stats:
                    sec_stats[f.secretaria_id]["contratos_vencendo_30"] += 1
            elif dias_rest <= 30:
                radar_vencimentos["d30"].append(item_v)
                if f.secretaria_id in sec_stats:
                    sec_stats[f.secretaria_id]["contratos_vencendo_30"] += 1
            elif dias_rest <= 60:
                radar_vencimentos["d60"].append(item_v)
            elif dias_rest <= 90:
                radar_vencimentos["d90"].append(item_v)
        elif is_cc:
            radar_vencimentos["sem_termino_com_cont"] += 1

        # Ranking por Padrinho / Liderança
        if f.padrinho_id and f.padrinho:
            if f.padrinho_id not in padrinho_agg:
                padrinho_agg[f.padrinho_id] = {
                    "id": f.padrinho_id,
                    "nome": f.padrinho.nome,
                    "total_indicados": 0,
                    "com_e_cont": 0,
                    "folha_mensal": 0.0,
                    "secretarias": set(),
                    "titulo_regular": 0,
                }
            pa = padrinho_agg[f.padrinho_id]
            pa["total_indicados"] += 1
            if is_cc:
                pa["com_e_cont"] += 1
            pa["folha_mensal"] += sal
            if f.secretaria:
                pa["secretarias"].add(f.secretaria.sigla or f.secretaria.nome)
            if (f.titulo_eleitor or "").strip() and (f.zona_eleitoral or "").strip() and (f.secao_eleitoral or "").strip():
                pa["titulo_regular"] += 1

        # Lista filtrada para tabela executiva
        if _matches_filters(f):
            dias_v = (f.dt_termino - hoje).days if f.dt_termino else None
            servidores_filtrados.append(
                {
                    "id": f.id,
                    "nome": f.nome,
                    "cpf": f.cpf or "---",
                    "secretaria_id": f.secretaria_id,
                    "secretaria_nome": f.secretaria.nome if f.secretaria else "---",
                    "secretaria_sigla": (f.secretaria.sigla or f.secretaria.nome[:14]) if f.secretaria else "---",
                    "local_nome": f.local_trabalho.nome if f.local_trabalho else "Não Definido",
                    "funcao_nome": f.funcao.nome if f.funcao else "Não Definida",
                    "tipo_vinculo": f.tipo_vinculo or "Não Informado",
                    "categoria_vinculo": cat,
                    "remuneracao_val": sal,
                    "remuneracao_fmt": _format_brl(sal) if sal > 0 else "Não informada",
                    "padrinho_nome": f.padrinho.nome if f.padrinho else "---",
                    "validado": bool(f.validado),
                    "dt_inicio_fmt": f.dt_inicio.strftime("%d/%m/%Y") if f.dt_inicio else "---",
                    "dt_termino_fmt": f.dt_termino.strftime("%d/%m/%Y") if f.dt_termino else "---",
                    "dias_restantes": dias_v,
                    "completude_pct": pct_comp,
                    "eleitoral_ok": bool((f.titulo_eleitor or "").strip() and (f.zona_eleitoral or "").strip() and (f.secao_eleitoral or "").strip()),
                }
            )

    # Ordena listas de vencimento por urgência
    for key in ("vencidos", "d15", "d30", "d60", "d90"):
        radar_vencimentos[key].sort(key=lambda x: x["dias_restantes"])

    # 4. Finaliza Termômetro de Secretarias
    secretarias_ranking = []
    for st in sec_stats.values():
        st["sem_vagas"] = _semaforo_teto(st["com_e_cont"], st["teto_comissionados"])
        st["sem_folha"] = _semaforo_teto(st["folha_mensal"], st["teto_folha_mensal"])
        st["folha_mensal_fmt"] = _format_brl(st["folha_mensal"])
        st["folha_com_cont_fmt"] = _format_brl(st["folha_com_cont"])
        st["teto_folha_fmt"] = _format_brl(st["teto_folha_mensal"]) if st["teto_folha_mensal"] > 0 else "Não definido"
        secretarias_ranking.append(st)
    secretarias_ranking.sort(key=lambda x: (x["com_e_cont"], x["folha_mensal"], x["total_ativos"]), reverse=True)

    # 5. Acúmulos de CPF (Cross-Secretaria & Intra-Secretaria)
    acumulos_cpf = []
    for cpf_d, group in cpf_groups.items():
        if len(group) < 2:
            continue
        sec_ids_distinct = {g.secretaria_id for g in group}
        soma_sal = sum(get_salario_valor(g) for g in group)
        acumulos_cpf.append(
            {
                "cpf_limpo": cpf_d,
                "cpf_formatado": f"{cpf_d[:3]}.{cpf_d[3:6]}.{cpf_d[6:9]}-{cpf_d[9:]}",
                "nome": group[0].nome,
                "qtd_vinculos": len(group),
                "multi_secretaria": len(sec_ids_distinct) > 1,
                "soma_remuneracao": soma_sal,
                "soma_remuneracao_fmt": _format_brl(soma_sal),
                "vinculos": [
                    {
                        "id": g.id,
                        "nome": g.nome,
                        "secretaria": g.secretaria.nome if g.secretaria else "---",
                        "sigla": (g.secretaria.sigla or g.secretaria.nome[:12]) if g.secretaria else "---",
                        "funcao": g.funcao.nome if g.funcao else "---",
                        "tipo_vinculo": g.tipo_vinculo or "---",
                        "remuneracao_fmt": _format_brl(get_salario_valor(g)),
                    }
                    for g in group
                ],
            }
        )
    acumulos_cpf.sort(key=lambda x: (x["multi_secretaria"], x["qtd_vinculos"], x["soma_remuneracao"]), reverse=True)

    # 6. Ranking Lideranças / Padrinhos
    ranking_padrinhos = []
    for pa in padrinho_agg.values():
        pct_tit = round((pa["titulo_regular"] / pa["total_indicados"]) * 100.0, 1) if pa["total_indicados"] else 0.0
        ranking_padrinhos.append(
            {
                "id": pa["id"],
                "nome": pa["nome"],
                "total_indicados": pa["total_indicados"],
                "com_e_cont": pa["com_e_cont"],
                "folha_mensal": pa["folha_mensal"],
                "folha_mensal_fmt": _format_brl(pa["folha_mensal"]),
                "secretarias_lista": sorted(pa["secretarias"]),
                "qtd_secretarias": len(pa["secretarias"]),
                "pct_titulo_regular": pct_tit,
            }
        )
    ranking_padrinhos.sort(key=lambda x: (x["total_indicados"], x["folha_mensal"]), reverse=True)

    # 7. Evolução Mensal (Últimos 12 meses: Admissões x Rescisões)
    meses_labels = []
    meses_keys = []
    ano_cur, mes_cur = hoje.year, hoje.month
    for offset in range(11, -1, -1):
        m_total = (ano_cur * 12 + (mes_cur - 1)) - offset
        a = m_total // 12
        m = (m_total % 12) + 1
        meses_keys.append((a, m))
        meses_labels.append(f"{m:02d}/{str(a)[2:]}")

    adm_by_ym: Dict[Tuple[int, int], int] = defaultdict(int)
    for f in todos_ativos:
        ref_dt = f.dt_inicio or (f.data_criacao.date() if f.data_criacao else None)
        if ref_dt:
            adm_by_ym[(ref_dt.year, ref_dt.month)] += 1

    resc_by_ym: Dict[Tuple[int, int], int] = defaultdict(int)
    for r in RescisaoHistorico.query.all():
        ref_r = r.data_saida or (r.data_geracao.date() if r.data_geracao else None)
        if ref_r:
            resc_by_ym[(ref_r.year, ref_r.month)] += 1

    evolucao_mensal = {
        "labels": meses_labels,
        "admissoes": [adm_by_ym[k] for k in meses_keys],
        "rescisoes": [resc_by_ym[k] for k in meses_keys],
    }

    # 8. Alertas Recentes de Segurança & Auditoria + Status do Último Backup
    alertas_seguranca = (
        LogAuditoria.query.filter(
            (LogAuditoria.nivel == "SECURITY")
            | (LogAuditoria.acao.in_(["ALERTA_ACUMULO_CPF", "VIOLAÇÃO DE ACESSO", "BLOQUEIO_FORCA_BRUTA"]))
        )
        .order_by(LogAuditoria.data_hora.desc())
        .limit(15)
        .all()
    )
    alertas_seguranca_list = [
        {
            "id": a.id,
            "acao": a.acao,
            "alvo": a.alvo,
            "usuario": a.usuario.username if a.usuario else "Sistema",
            "ip": a.ip_origem or "---",
            "data_hora_fmt": pytz.utc.localize(a.data_hora).astimezone(FUSO_BR).strftime("%d/%m/%Y %H:%M") if a.data_hora else "---",
        }
        for a in alertas_seguranca
    ]

    ultimo_bkp = (
        BackupHistorico.query.filter(
            BackupHistorico.tipo.in_(["MANUAL", "PRE_RESTORE"]),
            BackupHistorico.status == "CONCLUIDO",
        )
        .order_by(BackupHistorico.data_hora.desc())
        .first()
    )
    backup_status = None
    if ultimo_bkp and ultimo_bkp.data_hora:
        dias_bkp = (datetime.utcnow() - ultimo_bkp.data_hora).days
        backup_status = {
            "data_fmt": pytz.utc.localize(ultimo_bkp.data_hora).astimezone(FUSO_BR).strftime("%d/%m/%Y às %H:%M"),
            "dias_atras": dias_bkp,
            "total_registros": ultimo_bkp.total_registros or 0,
            "saudavel": dias_bkp <= 7,
        }

    total_com_e_cont_mun = total_comissionados_mun + total_contratados_mun
    folha_filtrada = sum(s["remuneracao_val"] for s in servidores_filtrados)
    ticket_medio_com_cont = (folha_mensal_com_cont / total_com_e_cont_mun) if total_com_e_cont_mun else 0.0
    completude_media = round(completude_soma / total_ativos_municipio, 1) if total_ativos_municipio else 0.0

    # Contratos gerados no exercício atual
    contratos_ano_atual = ContratoGerado.query.filter_by(ano_exercicio=hoje.year).count()

    return {
        "gerado_em_fmt": _now_br().strftime("%d/%m/%Y às %H:%M"),
        "ano_atual": hoje.year,
        "ano_proximo": hoje.year + 1,
        "kpis": {
            "total_ativos": total_ativos_municipio,
            "total_comissionados": total_comissionados_mun,
            "total_contratados": total_contratados_mun,
            "total_com_e_cont": total_com_e_cont_mun,
            "pct_com_e_cont": round((total_com_e_cont_mun / total_ativos_municipio) * 100.0, 1) if total_ativos_municipio else 0.0,
            "total_efetivos": total_efetivos_mun,
            "total_terceirizados": total_terceirizados_mun,
            "total_outros": total_outros_mun,
            "folha_mensal_total": folha_mensal_total,
            "folha_mensal_total_fmt": _format_brl(folha_mensal_total),
            "folha_anual_total_fmt": _format_brl(folha_mensal_total * 13.0),
            "folha_mensal_com_cont": folha_mensal_com_cont,
            "folha_mensal_com_cont_fmt": _format_brl(folha_mensal_com_cont),
            "folha_anual_com_cont_fmt": _format_brl(folha_mensal_com_cont * 13.0),
            "ticket_medio_com_cont_fmt": _format_brl(ticket_medio_com_cont),
            "sem_remuneracao_com_cont": sem_remuneracao_com_cont,
            "pendentes_validacao_total": pendentes_validacao_total,
            "pendentes_validacao_com_cont": pendentes_validacao_com_cont,
            "eleitoral_regular_pct": round((eleitoral_regular_total / total_ativos_municipio) * 100.0, 1) if total_ativos_municipio else 0.0,
            "completude_media": completude_media,
            "qtd_secretarias": len(secretarias),
            "qtd_unidades": LocalTrabalho.query.count(),
            "qtd_acumulos_cpf": len(acumulos_cpf),
            "qtd_acumulos_multi_sec": sum(1 for a in acumulos_cpf if a["multi_secretaria"]),
            "qtd_vencidos": len(radar_vencimentos["vencidos"]),
            "qtd_vencendo_30": len(radar_vencimentos["d15"]) + len(radar_vencimentos["d30"]),
            "qtd_vencendo_90": len(radar_vencimentos["d15"]) + len(radar_vencimentos["d30"]) + len(radar_vencimentos["d60"]) + len(radar_vencimentos["d90"]),
            "contratos_ano_atual": contratos_ano_atual,
            "filtrado_qtd": len(servidores_filtrados),
            "filtrado_folha_fmt": _format_brl(folha_filtrada),
        },
        "secretarias_ranking": secretarias_ranking,
        "acumulos_cpf": acumulos_cpf,
        "radar_vencimentos": radar_vencimentos,
        "ranking_padrinhos": ranking_padrinhos,
        "evolucao_mensal": evolucao_mensal,
        "vinculos_dist": dict(sorted(vinculos_dist.items(), key=lambda x: x[1], reverse=True)),
        "servidores_filtrados": servidores_filtrados,
        "alertas_seguranca": alertas_seguranca_list,
        "backup_status": backup_status,
        "secretarias": secretarias,
        "padrinhos": padrinhos_lista,
        "filtros": {
            "secretaria_id": filtro_secretaria_id,
            "escopo": filtro_escopo,
            "padrinho_id": filtro_padrinho_id,
            "validacao": filtro_validacao,
            "busca": filtro_busca,
        },
    }


def get_dossie_servidor_360(models: Dict[str, Any], func_id: int) -> Optional[Dict[str, Any]]:
    """Retorna o Raio-X 360° completo de um servidor para o Gabinete do Prefeito."""
    Funcionario = models["Funcionario"]
    HistoricoLotacao = models["HistoricoLotacao"]
    ContratoGerado = models["ContratoGerado"]
    RegistroPonto = models["RegistroPonto"]
    JustificativaFalta = models["JustificativaFalta"]
    LocalVotacao = models["LocalVotacao"]
    normalizar_num_eleit = models["normalizar_numero_eleitoral"]

    f = Funcionario.query.get(func_id)
    if not f:
        return None

    sal = get_salario_valor(f)
    pct_comp, faltantes = calc_completude_servidor(f)
    cpf_d = get_cpf_digits(f)

    # Verifica se possui outros vínculos ativos com o mesmo CPF
    outros_vinculos = []
    if len(cpf_d) == 11:
        mesmos = (
            Funcionario.query.filter(
                (Funcionario.cpf_limpo == cpf_d) | (Funcionario.cpf == f.cpf),
                Funcionario.id != f.id,
                (Funcionario.ativo == True) | (Funcionario.ativo.is_(None)),
            )
            .all()
        )
        for m in mesmos:
            outros_vinculos.append(
                {
                    "id": m.id,
                    "secretaria": m.secretaria.nome if m.secretaria else "---",
                    "funcao": m.funcao.nome if m.funcao else "---",
                    "tipo_vinculo": m.tipo_vinculo or "---",
                    "remuneracao_fmt": _format_brl(get_salario_valor(m)),
                }
            )

    # Identifica o Colégio Eleitoral correspondente à Zona/Seção
    colegio_eleitoral = None
    f_zona = normalizar_num_eleit(f.zona_eleitoral)
    f_secao = normalizar_num_eleit(f.secao_eleitoral)
    if f_secao:
        for loc in LocalVotacao.query.all():
            loc_zona = normalizar_num_eleit(loc.zona_eleitoral)
            if (not f_zona or f_zona == loc_zona) and f_secao in loc.get_secoes_normalized():
                colegio_eleitoral = {
                    "nome": loc.nome,
                    "bairro": loc.bairro or "---",
                    "zona": loc.zona_eleitoral,
                }
                break

    # Histórico de movimentações
    historico = (
        HistoricoLotacao.query.filter_by(funcionario_id=f.id)
        .order_by(HistoricoLotacao.data_mudanca.desc())
        .limit(15)
        .all()
    )
    historico_list = [
        {
            "data_fmt": h.data_mudanca.strftime("%d/%m/%Y %H:%M") if h.data_mudanca else "---",
            "antiga_secretaria": h.antiga_secretaria or "---",
            "antigo_local": h.antigo_local or "---",
            "antiga_funcao": h.antiga_funcao or "---",
            "quem_mudou": h.quem_mudou.username if h.quem_mudou else "Sistema",
        }
        for h in historico
    ]

    # Contratos gerados
    contratos = (
        ContratoGerado.query.filter_by(funcionario_id=f.id)
        .order_by(ContratoGerado.data_geracao.desc())
        .limit(10)
        .all()
    )
    contratos_list = [
        {
            "id": c.id,
            "num_contrato": c.num_contrato,
            "ano_exercicio": c.ano_exercicio,
            "funcao": c.funcao_nome or "---",
            "remuneracao": c.remuneracao or "---",
            "periodo": f"{c.dt_inicio.strftime('%d/%m/%Y') if c.dt_inicio else '?'} a {c.dt_termino.strftime('%d/%m/%Y') if c.dt_termino else '?'}",
        }
        for c in contratos
    ]

    # Ponto (últimos 30 dias + total)
    limite_30 = _now_br() - timedelta(days=30)
    pontos_total = RegistroPonto.query.filter_by(funcionario_id=f.id).count()
    pontos_30d = RegistroPonto.query.filter(
        RegistroPonto.funcionario_id == f.id,
        RegistroPonto.data_hora >= limite_30,
    ).count()
    ultimo_ponto = (
        RegistroPonto.query.filter_by(funcionario_id=f.id)
        .order_by(RegistroPonto.data_hora.desc())
        .first()
    )

    # Atestados / Justificativas
    atestados = (
        JustificativaFalta.query.filter_by(funcionario_id=f.id)
        .order_by(JustificativaFalta.data_solicitacao.desc())
        .limit(10)
        .all()
    )
    atestados_list = [
        {
            "protocolo": a.protocolo,
            "data_fmt": a.data_inicio_afastamento.strftime("%d/%m/%Y") if a.data_inicio_afastamento else "---",
            "dias": a.dias_solicitados or 1,
            "motivo": a.motivo_ausencia or "---",
            "status": a.status or "PENDENTE",
        }
        for a in atestados
    ]

    hoje = _today_br()
    dias_restantes = (f.dt_termino - hoje).days if f.dt_termino else None

    return {
        "id": f.id,
        "nome": f.nome,
        "cpf": f.cpf or "---",
        "rg": f.rg or "---",
        "orgao_emissor_rg": f.orgao_emissor_rg or "",
        "data_nasc_fmt": f.data_nasc.strftime("%d/%m/%Y") if f.data_nasc else "---",
        "pis": f.pis or "---",
        "mae": f.mae or "---",
        "pai": f.pai or "---",
        "estado_civil": f.estado_civil or "---",
        "escolaridade": f.escolaridade or "---",
        "especialidade": f.especialidade or "",
        "telefone": f.telefone or "---",
        "email": f.email or "---",
        "endereco": ", ".join(filter(None, [f.endereco, f.bairro, f"{f.cidade or ''}/{f.uf or ''}".strip("/")])) or "---",
        "tipo_sanguineo": f.tipo_sanguineo or "---",
        "contato_emergencia": f"{f.contato_emergencia_nome or ''} ({f.contato_emergencia_tel or ''})".strip(" ()") or "---",
        "secretaria_nome": f.secretaria.nome if f.secretaria else "---",
        "secretaria_sigla": (f.secretaria.sigla or "") if f.secretaria else "",
        "local_trabalho": f.local_trabalho.nome if f.local_trabalho else "Não Definido",
        "funcao": f.funcao.nome if f.funcao else "Não Definida",
        "tipo_vinculo": f.tipo_vinculo or "Não Informado",
        "categoria_vinculo": classify_vinculo(f.tipo_vinculo),
        "num_vinculo": f.num_vinculo or "---",
        "jornada": f.jornada_trabalho or "---",
        "remuneracao_fmt": _format_brl(sal) if sal > 0 else "Não informada",
        "remuneracao_val": sal,
        "dt_inicio_fmt": f.dt_inicio.strftime("%d/%m/%Y") if f.dt_inicio else "---",
        "dt_termino_fmt": f.dt_termino.strftime("%d/%m/%Y") if f.dt_termino else "---",
        "dias_restantes": dias_restantes,
        "validado": bool(f.validado),
        "ativo": bool(f.ativo is not False),
        "banco": f.banco or "---",
        "agencia": f.agencia or "---",
        "conta": f.conta or "---",
        "tipo_conta": f.tipo_conta or "",
        "foi_indicacao": bool(f.foi_indicacao),
        "padrinho_nome": f.padrinho.nome if f.padrinho else "Sem indicação registrada",
        "titulo_eleitor": f.titulo_eleitor or "---",
        "zona_eleitoral": f.zona_eleitoral or "---",
        "secao_eleitoral": f.secao_eleitoral or "---",
        "colegio_eleitoral": colegio_eleitoral,
        "completude_pct": pct_comp,
        "pendencias_cadastro": faltantes,
        "outros_vinculos_ativos": outros_vinculos,
        "historico_lotacao": historico_list,
        "contratos": contratos_list,
        "ponto": {
            "total": pontos_total,
            "ultimos_30d": pontos_30d,
            "ultimo_registro": ultimo_ponto.data_hora.strftime("%d/%m/%Y %H:%M") if ultimo_ponto and ultimo_ponto.data_hora else "Sem registros",
        },
        "atestados": atestados_list,
    }


def export_prefeito_excel_bytes(dashboard_data: Dict[str, Any]) -> bytes:
    """Gera pasta de trabalho Excel (.xlsx) executiva multi-abas para o Gabinete do Prefeito."""
    import pandas as pd

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        # Aba 1: Resumo por Secretaria
        df_sec = pd.DataFrame(
            [
                {
                    "Secretaria": s["nome"],
                    "Sigla": s["sigla"],
                    "Titular": s["secretario_nome"],
                    "Total Ativos": s["total_ativos"],
                    "Comissionados": s["comissionados"],
                    "Contratados": s["contratados"],
                    "Comiss. + Contrat.": s["com_e_cont"],
                    "Teto Comiss./Contr.": s["teto_comissionados"],
                    "% Teto Vagas": s["sem_vagas"]["pct"],
                    "Efetivos": s["efetivos"],
                    "Terceirizados": s["terceirizados"],
                    "Folha Mensal (R$)": round(s["folha_mensal"], 2),
                    "Folha Comiss./Contr. (R$)": round(s["folha_com_cont"], 2),
                    "Teto Folha (R$)": round(s["teto_folha_mensal"], 2),
                    "% Teto Folha": s["sem_folha"]["pct"],
                    "Pendentes Validação": s["pendentes"],
                    "Vencidos": s["contratos_vencidos"],
                    "Vencendo 30d": s["contratos_vencendo_30"],
                }
                for s in dashboard_data["secretarias_ranking"]
            ]
        )
        df_sec.to_excel(writer, sheet_name="Resumo Secretarias", index=False)

        # Aba 2: Servidores Filtrados
        df_srv = pd.DataFrame(
            [
                {
                    "ID": s["id"],
                    "Nome": s["nome"],
                    "CPF": s["cpf"],
                    "Secretaria": s["secretaria_nome"],
                    "Local / Unidade": s["local_nome"],
                    "Função / Cargo": s["funcao_nome"],
                    "Vínculo": s["tipo_vinculo"],
                    "Remuneração (R$)": round(s["remuneracao_val"], 2),
                    "Admissão": s["dt_inicio_fmt"],
                    "Término": s["dt_termino_fmt"],
                    "Padrinho / Indicação": s["padrinho_nome"],
                    "Validado": "SIM" if s["validado"] else "PENDENTE",
                    "Completude (%)": s["completude_pct"],
                }
                for s in dashboard_data["servidores_filtrados"]
            ]
        )
        df_srv.to_excel(writer, sheet_name="Servidores Escopo", index=False)

        # Aba 3: Radar de Vencimentos
        radar_rows = []
        for faixa, label in [
            ("vencidos", "VENCIDO"),
            ("d15", "CRÍTICO (<=15d)"),
            ("d30", "ATENÇÃO (16-30d)"),
            ("d60", "PLANEJAMENTO (31-60d)"),
            ("d90", "PRÓXIMOS 90d"),
        ]:
            for item in dashboard_data["radar_vencimentos"][faixa]:
                radar_rows.append(
                    {
                        "Faixa": label,
                        "Dias Restantes": item["dias_restantes"],
                        "Nome": item["nome"],
                        "CPF": item["cpf"],
                        "Secretaria": item["secretaria"],
                        "Função": item["funcao"],
                        "Vínculo": item["tipo_vinculo"],
                        "Vencimento": item["dt_termino_fmt"],
                        "Remuneração (R$)": round(item["remuneracao_val"], 2),
                    }
                )
        df_rad = pd.DataFrame(radar_rows or [{"Info": "Nenhum contrato vencido ou vencendo nos próximos 90 dias."}])
        df_rad.to_excel(writer, sheet_name="Radar Vencimentos", index=False)

        # Aba 4: Acúmulos de CPF
        acum_rows = []
        for a in dashboard_data["acumulos_cpf"]:
            for v in a["vinculos"]:
                acum_rows.append(
                    {
                        "CPF": a["cpf_formatado"],
                        "Multi-Secretaria": "SIM" if a["multi_secretaria"] else "MESMA PASTA",
                        "Qtd Vínculos": a["qtd_vinculos"],
                        "Soma Salarial (R$)": round(a["soma_remuneracao"], 2),
                        "Servidor": v["nome"],
                        "Secretaria": v["secretaria"],
                        "Função": v["funcao"],
                        "Vínculo": v["tipo_vinculo"],
                        "Remuneração": v["remuneracao_fmt"],
                    }
                )
        df_ac = pd.DataFrame(acum_rows or [{"Info": "Nenhum acúmulo de CPF detectado na base ativa."}])
        df_ac.to_excel(writer, sheet_name="Acumulos CPF", index=False)

        # Aba 5: Ranking Lideranças / Padrinhos
        df_pad = pd.DataFrame(
            [
                {
                    "Liderança / Padrinho": p["nome"],
                    "Total Indicados": p["total_indicados"],
                    "Comiss. + Contrat.": p["com_e_cont"],
                    "Impacto Mensal (R$)": round(p["folha_mensal"], 2),
                    "Qtd Secretarias": p["qtd_secretarias"],
                    "Secretarias": ", ".join(p["secretarias_lista"]),
                    "% Título Regular": p["pct_titulo_regular"],
                }
                for p in dashboard_data["ranking_padrinhos"]
            ]
            or [{"Info": "Sem indicações registradas."}]
        )
        df_pad.to_excel(writer, sheet_name="Liderancas Indicacoes", index=False)

    output.seek(0)
    return output.getvalue()
