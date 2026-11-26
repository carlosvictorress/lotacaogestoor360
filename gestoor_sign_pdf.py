"""
Motor de Geração Determinística de PDF, QR Code e Relatório de Evidências — GESTOOR SIGN
========================================================================================
Utiliza ReportLab (puro Python) + QRCode/Pillow para gerar no servidor:
1. PDF Base do Contrato Administrativo (versão exata conferida antes da assinatura) + SHA-256.
2. PDF Final Assinado Eletronicamente (Contrato Integral + Selo Eletrônico + Relatório de Evidências + QR Code) + SHA-256.
3. PDF Autônomo do Relatório de Evidências para auditoria externa (TCE/MP/Controle Interno).

Identidade visual Gestoor360: Verde-escuro (#0B3D2E), Verde vivo (#10B981), Amarelo (#EAB308), Branco (#FFFFFF).
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape

import qrcode
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Paleta oficial Gestoor360 / Gestoor Sign
COR_VERDE_ESCURO = colors.HexColor("#0B3D2E")
COR_VERDE_MEDIO = colors.HexColor("#14532D")
COR_VERDE_VIVO = colors.HexColor("#10B981")
COR_VERDE_CLARO_BG = colors.HexColor("#ECFDF5")
COR_AMARELO = colors.HexColor("#EAB308")
COR_AMARELO_BG = colors.HexColor("#FEFCE8")
COR_TEXTO = colors.HexColor("#111827")
COR_MUTED = colors.HexColor("#4B5563")
COR_BORDA = colors.HexColor("#D1D5DB")


def _esc(val: Any) -> str:
    return escape(str(val if val is not None else ""))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def gerar_qrcode_png_bytes(url: str, box_size: int = 6, border: int = 2) -> bytes:
    """Gera imagem PNG de QR Code em memória."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(url or "")
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0B3D2E", back_color="#FFFFFF")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def gerar_qrcode_data_uri(url: str) -> str:
    """Retorna data URI base64 (data:image/png;base64,...) para renderização inline no HTML."""
    raw = gerar_qrcode_png_bytes(url, box_size=5, border=2)
    return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")


def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "G360Title",
            parent=base["Normal"],
            fontName="Times-Bold",
            fontSize=12,
            leading=15,
            alignment=TA_CENTER,
            textColor=colors.black,
            spaceAfter=6,
        ),
        "ementa": ParagraphStyle(
            "G360Ementa",
            parent=base["Normal"],
            fontName="Times-Bold",
            fontSize=9,
            leading=12,
            alignment=TA_JUSTIFY,
            textColor=colors.black,
        ),
        "body_indent": ParagraphStyle(
            "G360BodyIndent",
            parent=base["Normal"],
            fontName="Times-Roman",
            fontSize=10.5,
            leading=14.5,
            alignment=TA_JUSTIFY,
            firstLineIndent=20,
            spaceAfter=6,
            textColor=colors.black,
        ),
        "heading": ParagraphStyle(
            "G360Heading",
            parent=base["Normal"],
            fontName="Times-Bold",
            fontSize=10.5,
            leading=14,
            spaceBefore=7,
            spaceAfter=3,
            textColor=colors.black,
        ),
        "clause": ParagraphStyle(
            "G360Clause",
            parent=base["Normal"],
            fontName="Times-Roman",
            fontSize=10.5,
            leading=14.5,
            alignment=TA_JUSTIFY,
            spaceAfter=5,
            textColor=colors.black,
        ),
        "item": ParagraphStyle(
            "G360Item",
            parent=base["Normal"],
            fontName="Times-Roman",
            fontSize=10.5,
            leading=14,
            alignment=TA_JUSTIFY,
            leftIndent=16,
            spaceAfter=4,
            textColor=colors.black,
        ),
        "center_bold": ParagraphStyle(
            "G360CenterBold",
            parent=base["Normal"],
            fontName="Times-Bold",
            fontSize=10.5,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.black,
        ),
        "center": ParagraphStyle(
            "G360Center",
            parent=base["Normal"],
            fontName="Times-Roman",
            fontSize=10,
            leading=13.5,
            alignment=TA_CENTER,
            textColor=colors.black,
        ),
        # Estilos modernos do Relatório de Evidências (Sans-Serif Helvetica)
        "ev_banner_title": ParagraphStyle(
            "EvBannerTitle",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.white,
        ),
        "ev_banner_sub": ParagraphStyle(
            "EvBannerSub",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#D1FAE5"),
        ),
        "ev_sec": ParagraphStyle(
            "EvSec",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=COR_VERDE_ESCURO,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "ev_label": ParagraphStyle(
            "EvLabel",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=COR_MUTED,
        ),
        "ev_val": ParagraphStyle(
            "EvVal",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=COR_TEXTO,
        ),
        "ev_mono": ParagraphStyle(
            "EvMono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=COR_VERDE_ESCURO,
        ),
        "ev_quote": ParagraphStyle(
            "EvQuote",
            parent=base["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8.5,
            leading=12,
            alignment=TA_JUSTIFY,
            textColor=COR_VERDE_ESCURO,
        ),
        "ev_small": ParagraphStyle(
            "EvSmall",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=COR_MUTED,
        ),
    }


def _timbre_flowable(timbre_path: Optional[str]) -> Optional[Image]:
    if not timbre_path or not os.path.isfile(timbre_path):
        return None
    try:
        img = Image(timbre_path)
        max_w = 174 * mm
        max_h = 24 * mm
        iw, ih = img.imageWidth, img.imageHeight
        if iw > 0 and ih > 0:
            ratio = min(max_w / iw, max_h / ih)
            img.drawWidth = iw * ratio
            img.drawHeight = ih * ratio
        img.hAlign = "CENTER"
        return img
    except Exception:
        return None


def _assinatura_img_flowable(data_uri: Optional[str], max_w_mm: float = 54.0, max_h_mm: float = 16.0) -> Optional[Image]:
    """Converte data URI base64 de assinatura em flowable Image proporcional para ReportLab."""
    if not data_uri or not isinstance(data_uri, str):
        return None
    try:
        b64_part = data_uri.split(",", 1)[1] if "," in data_uri else data_uri
        raw = base64.b64decode(b64_part)
        img = Image(io.BytesIO(raw))
        iw, ih = img.imageWidth, img.imageHeight
        if iw > 0 and ih > 0:
            ratio = min((max_w_mm * mm) / iw, (max_h_mm * mm) / ih)
            img.drawWidth = iw * ratio
            img.drawHeight = ih * ratio
        img.hAlign = "CENTER"
        return img
    except Exception:
        return None


def _draw_custom_seal_on_canvas(canvas, selo: Dict[str, Any], x_pct: float, y_pct: float):
    """Desenha o selo eletrônico oficial com QR Code diretamente no ponto (x_pct, y_pct) da página A4."""
    page_w, page_h = A4
    box_w = 96 * mm
    box_h = 26 * mm

    # Converte porcentagem (origem no topo esquerdo, igual ao navegador) para coordenadas PDF (origem inferior esquerda)
    cx = (float(x_pct) / 100.0) * page_w
    cy = page_h - ((float(y_pct) / 100.0) * page_h)

    x0 = max(12 * mm, min(cx - (box_w / 2.0), page_w - box_w - 12 * mm))
    y0 = max(16 * mm, min(cy - (box_h / 2.0), page_h - box_h - 14 * mm))

    canvas.saveState()
    # Fundo verde claro + borda verde vivo + faixa esquerda verde escuro
    canvas.setFillColor(COR_VERDE_CLARO_BG)
    canvas.setStrokeColor(COR_VERDE_VIVO)
    canvas.setLineWidth(1.1)
    canvas.roundRect(x0, y0, box_w, box_h, 3, stroke=1, fill=1)

    canvas.setFillColor(COR_VERDE_ESCURO)
    canvas.rect(x0, y0, 3 * mm, box_h, stroke=0, fill=1)

    # QR Code à direita
    qr_size = 21 * mm
    qr_x = x0 + box_w - qr_size - 2.5 * mm
    qr_y = y0 + (box_h - qr_size) / 2.0
    try:
        qr_bytes = gerar_qrcode_png_bytes(selo.get("validar_url", ""), box_size=4, border=1)
        canvas.drawImage(ImageReader(io.BytesIO(qr_bytes)), qr_x, qr_y, width=qr_size, height=qr_size)
    except Exception:
        pass

    # Textos do selo
    tx = x0 + 5 * mm
    canvas.setFillColor(COR_VERDE_ESCURO)
    canvas.setFont("Helvetica-Bold", 7.2)
    canvas.drawString(tx, y0 + box_h - 5.2 * mm, "ASSINADO ELETRONICAMENTE — GESTOOR SIGN")

    canvas.setFillColor(COR_TEXTO)
    canvas.setFont("Helvetica-Bold", 6.8)
    canvas.drawString(tx, y0 + box_h - 9.4 * mm, str(selo.get("servidor_nome") or "")[:36])

    canvas.setFont("Helvetica", 6.4)
    canvas.setFillColor(COR_MUTED)
    canvas.drawString(tx, y0 + box_h - 13.0 * mm, f"CPF: {selo.get('servidor_cpf_mascarado') or ''}  |  Simples (Lei 14.063/2020)")
    canvas.drawString(tx, y0 + box_h - 16.6 * mm, f"Data/Hora: {selo.get('assinado_em_brt') or ''}")
    canvas.setFont("Courier-Bold", 6.5)
    canvas.setFillColor(COR_VERDE_ESCURO)
    canvas.drawString(tx, y0 + box_h - 20.4 * mm, f"Cód: {selo.get('codigo_validacao') or ''}")
    canvas.setFont("Helvetica", 5.8)
    canvas.setFillColor(COR_MUTED)
    canvas.drawString(tx, y0 + 2.2 * mm, f"RH: {str(selo.get('tecnico_nome') or '')[:34]}")
    canvas.restoreState()


def _draw_page_footer(canvas, doc, rodape_texto: str, selo_eletronico: Optional[Dict[str, Any]] = None, total_paginas_contrato: int = 5):
    canvas.saveState()
    local_cfg = (selo_eletronico or {}).get("local_assinatura") or {}
    modo = str(local_cfg.get("modo") or "BLOCO_CONTRATADO").upper()

    # Rubrica eletrônica no rodapé de todas as páginas do contrato quando escolhido
    if selo_eletronico and modo == "RODAPE_TODAS_PAGINAS" and doc.page <= total_paginas_contrato:
        canvas.setFillColor(COR_VERDE_CLARO_BG)
        canvas.setStrokeColor(COR_VERDE_VIVO)
        canvas.setLineWidth(0.7)
        canvas.roundRect(18 * mm, 14.2 * mm, A4[0] - 36 * mm, 6.2 * mm, 2, stroke=1, fill=1)
        canvas.setFont("Helvetica-Bold", 6.6)
        canvas.setFillColor(COR_VERDE_ESCURO)
        rubrica = (
            f"GESTOOR SIGN (Assinatura Eletrônica Simples) • {selo_eletronico.get('servidor_nome')} "
            f"({selo_eletronico.get('servidor_cpf_mascarado')}) • {selo_eletronico.get('assinado_em_brt')} "
            f"• Cód: {selo_eletronico.get('codigo_validacao')}"
        )
        canvas.drawString(20 * mm, 16.2 * mm, rubrica[:120])

    # Posição personalizada desenhada diretamente na página e coordenadas escolhidas
    if selo_eletronico and modo == "POSICAO_PERSONALIZADA":
        alvo_pag = int(local_cfg.get("pagina") or 4)
        if doc.page == alvo_pag:
            _draw_custom_seal_on_canvas(
                canvas,
                selo_eletronico,
                float(local_cfg.get("x_pct") or 50.0),
                float(local_cfg.get("y_pct") or 66.0),
            )

    canvas.setStrokeColor(COR_BORDA)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
    canvas.setFont("Helvetica", 7.2)
    canvas.setFillColor(COR_MUTED)
    canvas.drawString(18 * mm, 9 * mm, rodape_texto[:105])
    canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Página {doc.page}")
    canvas.restoreState()


def _montar_corpo_contrato_story(
    contrato: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
    timbre_path: Optional[str],
    selo_eletronico: Optional[Dict[str, Any]] = None,
) -> List[Any]:
    story: List[Any] = []

    timbre = _timbre_flowable(timbre_path)
    if timbre:
        story.append(timbre)
        story.append(Spacer(1, 4 * mm))

    municipio_nome = (contrato.get("municipio_nome") or "Município de Valença do Piauí").strip()
    municipio_uf = (contrato.get("municipio_uf") or "PI").strip()
    municipio_cidade = (contrato.get("municipio_cidade") or "Valença do Piauí").strip()
    secretaria_nome = (contrato.get("secretaria_nome") or "SECRETARIA DE EDUCAÇÃO").strip()
    secretaria_cnpj = (contrato.get("secretaria_cnpj") or "06.095.146/0001-44").strip()
    secretaria_endereco = (
        contrato.get("secretaria_endereco")
        or "Rua Epaminondas Nogueira, nº 1425, Bairro São Francisco, na cidade de Valença do Piauí-PI"
    ).strip()

    num_contrato = contrato.get("num_contrato") or ""
    versao = int(contrato.get("versao") or 1)
    versao_txt = f" (Versão {versao})" if versao > 1 else ""

    story.append(
        Paragraph(
            f"CONTRATO ADMINISTRATIVO Nº {_esc(num_contrato)}{_esc(versao_txt)}",
            styles["title"],
        )
    )

    # Ementa à direita (mesmo padrão visual do contrato oficial)
    ementa_txt = (
        f"CONTRATO DE PRESTAÇÃO DE SERVIÇOS TEMPORÁRIO FIRMADO ENTRE O "
        f"{_esc(municipio_nome.upper())} – {_esc(secretaria_nome.upper())} E "
        f"{_esc((contrato.get('contratado_nome') or '').upper())} PARA ATUAÇÃO COMO "
        f"{_esc((contrato.get('funcao_nome') or '').upper())}, NOS TERMOS DO ART. 37, "
        f"INCISO IX DA CONSTITUIÇÃO FEDERAL."
    )
    tbl_ementa = Table(
        [["", Paragraph(ementa_txt, styles["ementa"])]],
        colWidths=[70 * mm, 104 * mm],
    )
    tbl_ementa.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(tbl_ementa)
    story.append(Spacer(1, 4 * mm))

    rep_cargo = contrato.get("representante_cargo") or f"Secretário(a) de {secretaria_nome}"
    preambulo = (
        f"Pelo presente instrumento particular, de um lado o "
        f"<b>{_esc(municipio_nome.upper())} – {_esc(secretaria_nome.upper())}</b>, "
        f"CNPJ de Nº {_esc(secretaria_cnpj)}, com sede na {_esc(secretaria_endereco)}, "
        f"representada neste ato por {_esc(rep_cargo)}, o(a) Sr.(a) {_esc(contrato.get('representante_nome') or '')}, "
        f"CPF/RG de nº {_esc(contrato.get('representante_rg_cpf') or '')}, residente e domiciliado(a) na "
        f"{_esc(contrato.get('representante_endereco') or '')}, doravante denominado <b>CONTRATANTE</b>, "
        f"e de outro lado o(a) Sr.(a) {_esc(contrato.get('contratado_nome') or '')}, "
        f"{_esc(contrato.get('contratado_nacionalidade') or 'brasileiro(a)')}, "
        f"{_esc(contrato.get('contratado_naturalidade') or 'piauiense')}, "
        f"{_esc(contrato.get('contratado_estado_civil') or 'solteiro(a)')}, "
        f"inscrito(a) com RG nº {_esc(contrato.get('contratado_rg') or '')} e "
        f"CPF nº {_esc(contrato.get('contratado_cpf') or '')}, residente e domiciliado(a) na "
        f"{_esc(contrato.get('contratado_endereco') or '')}, doravante denominado <b>CONTRATADO</b>, "
        f"têm, entre si, justo e contratado, com base no que dispõe o Art. 37, inciso IX da Constituição Federal, "
        f"mediante as cláusulas e condições que seguem:"
    )
    story.append(Paragraph(preambulo, styles["body_indent"]))

    # Cláusulas 1 a 12
    story.append(Paragraph("1 – DO OBJETO", styles["heading"]))
    story.append(
        Paragraph(
            f"<b>CLÁUSULA PRIMEIRA</b> – O objeto do presente contrato é a contratação do Servidor Temporário para "
            f"atender ao Excepcional Interesse Público, para a prestação de serviços na função de "
            f"{_esc(contrato.get('funcao_nome') or '')}, atendidas as determinações da {_esc(secretaria_nome)}, "
            f"conforme Constituição Federal, artigo 37, inciso IX.",
            styles["clause"],
        )
    )
    story.append(
        Paragraph(
            "<b>PARÁGRAFO ÚNICO</b> – Os trabalhos serão desenvolvidos em estrita observância às cláusulas deste "
            "contrato, principalmente no tocante às obrigações do CONTRATADO.",
            styles["clause"],
        )
    )

    story.append(Paragraph("2 – DO PREÇO", styles["heading"]))
    story.append(
        Paragraph(
            f"<b>CLÁUSULA SEGUNDA</b> – A CONTRATANTE pagará ao CONTRATADO o valor mensal de "
            f"{_esc(contrato.get('remuneracao_formatada') or 'R$0,00')} ({_esc(contrato.get('remuneracao_extenso') or '')}).",
            styles["clause"],
        )
    )
    story.append(
        Paragraph(
            "Pelos serviços contratados, estando incluídos nos mesmos todos os insumos, taxas, encargos e demais despesas;",
            styles["clause"],
        )
    )

    story.append(Paragraph("3 – DA JORNADA DE TRABALHO", styles["heading"]))
    story.append(
        Paragraph(
            f"<b>CLÁUSULA TERCEIRA</b> – A jornada de trabalho do CONTRATADO durante a vigência do presente contrato é de "
            f"{_esc(contrato.get('jornada_trabalho') or '')};",
            styles["clause"],
        )
    )

    story.append(Paragraph("4 – DO PRAZO", styles["heading"]))
    story.append(
        Paragraph(
            f"<b>CLÁUSULA QUARTA</b> – O contratado trabalhará em caráter de excepcionalidade, contados a partir de "
            f"{_esc(contrato.get('dt_inicio_extenso') or '')} a {_esc(contrato.get('dt_termino_extenso') or '')}.",
            styles["clause"],
        )
    )

    # PÁGINA 2 (espelha exatamente a paginação oficial do contrato_documento.html)
    story.append(PageBreak())
    t2 = _timbre_flowable(timbre_path)
    if t2:
        story.append(t2)
        story.append(Spacer(1, 3 * mm))

    story.append(
        Paragraph(
            "<b>PARÁGRAFO ÚNICO</b> – O presente contrato poderá ser rescindido a qualquer tempo por acordo entre as partes, "
            "ou unilateralmente pela CONTRATANTE no caso de o CONTRATADO deixar de cumprir qualquer uma das suas cláusulas, "
            "devendo prevalecer em todos os casos o interesse público.",
            styles["clause"],
        )
    )

    story.append(Paragraph("5 – DA EXECUÇÃO DOS SERVIÇOS", styles["heading"]))
    story.append(
        Paragraph(
            "<b>CLÁUSULA QUINTA</b> – Na execução dos serviços o CONTRATADO se obriga a respeitar, rigorosamente, durante o "
            "período de vigência deste contrato as normas de higiene e segurança, por cujos encargos responderá unilateralmente, "
            "devendo observar também os requisitos de qualidade, determinados pelo CONTRATANTE, através do setor responsável "
            "pela fiscalização, aprovação e liberação do serviço.",
            styles["clause"],
        )
    )
    story.append(
        Paragraph(
            "<b>PARÁGRAFO ÚNICO</b>: O CONTRATADO, sem prejuízo de sua responsabilidade, deverá comunicar à fiscalização do "
            "CONTRATANTE, por escrito, qualquer anormalidade verificada na execução ou no controle dos serviços, bem como "
            "qualquer fato que possa colocar em risco a segurança e a qualidade dos mesmos e sua execução dentro do prazo pactuado.",
            styles["clause"],
        )
    )

    story.append(Paragraph("6 – DAS OBRIGAÇÕES DO CONTRATANTE", styles["heading"]))
    story.append(Paragraph("<b>CLÁUSULA SEXTA</b> – São obrigações da CONTRATANTE:", styles["clause"]))
    story.append(Paragraph("I - Fornecer elementos necessários à realização do objeto deste contrato;", styles["item"]))
    story.append(Paragraph("II - Receber os serviços, procedendo-lhe a vistoria necessária e compatível com o objeto deste;", styles["item"]))
    story.append(Paragraph("III - Efetuar a retenção da contribuição previdenciária obrigatória sobre sua remuneração, para os fins da Lei 8.212/91 e Lei 8.213/91.", styles["item"]))

    story.append(Paragraph("7 – DAS OBRIGAÇÕES DO CONTRATADO", styles["heading"]))
    story.append(Paragraph("<b>CLÁUSULA SÉTIMA</b> – São obrigações do CONTRATADO:", styles["clause"]))
    story.append(Paragraph("I - Todas as despesas referentes ao objeto deste contrato, mão de obra, locomoção, seguro de acidente, impostos federais, estaduais e municipais, contribuições previdenciárias, encargos trabalhistas e quaisquer outras que forem devidas, relativamente à execução dos serviços ora contratados;", styles["item"]))
    story.append(Paragraph("II - Executar serviços ora contratados com esmero e dentro da melhor técnica, responsabilizando-se por quaisquer erros, falhas ou imperfeições que porventura ocorram;", styles["item"]))
    story.append(Paragraph("III - Responsabilizar-se pelos danos causados diretamente à Administração ou a terceiros, decorrentes de seus serviços;", styles["item"]))
    story.append(Paragraph("IV - Sujeitar-se à mais ampla e irrestrita fiscalização por parte do CONTRATANTE, prestando todos os esclarecimentos solicitados e atendendo às reclamações solicitadas;", styles["item"]))

    # PÁGINA 3
    story.append(PageBreak())
    t3 = _timbre_flowable(timbre_path)
    if t3:
        story.append(t3)
        story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("8 – DA DOTAÇÃO ORÇAMENTÁRIA", styles["heading"]))
    story.append(
        Paragraph(
            f"<b>CLÁUSULA OITAVA</b> – As despesas decorrentes do presente contrato correrão por conta de recursos "
            f"orçamentários consignados no Orçamento Anual do Município do exercício de {_esc(contrato.get('ano_exercicio') or '')}, "
            f"mais especificamente dos recursos do Fundo Nacional de Desenvolvimento da Educação (FUNDEB); Fundo de Participação "
            f"dos Municípios (FPM); do Imposto sobre a Propriedade de Veículos Automotores (IPVA); do Imposto sobre a Circulação "
            f"de Mercadorias e Serviços (ICMS) e da Arrecadação Própria do Município.",
            styles["clause"],
        )
    )

    story.append(Paragraph("9 – DAS PENALIDADES", styles["heading"]))
    story.append(
        Paragraph(
            f"<b>CLÁUSULA NONA</b> – Se o CONTRATADO não satisfazer os compromissos assumidos serão aplicadas as penalidades "
            f"previstas no Estatuto dos Servidores Públicos do {_esc(municipio_nome)} e demais normas administrativas aplicáveis.",
            styles["clause"],
        )
    )

    story.append(Paragraph("10 – DA RESCISÃO", styles["heading"]))
    story.append(Paragraph("<b>CLÁUSULA DÉCIMA</b> – Este contrato estará rescindido, automaticamente:", styles["clause"]))
    story.append(Paragraph("a) No final do prazo estipulado na Cláusula Quarta, desde que não tenha ocorrido prorrogação;", styles["item"]))
    story.append(Paragraph(f"b) Se a parte CONTRATADA incidir em qualquer das faltas arroladas no Estatuto dos Servidores Públicos do {_esc(municipio_nome)}.", styles["item"]))

    story.append(Paragraph("11 – DAS DISPOSIÇÕES GERAIS", styles["heading"]))
    story.append(
        Paragraph(
            f"<b>CLÁUSULA DÉCIMA PRIMEIRA</b> – Além das cláusulas que compõem o presente contrato, ficam sujeitas as partes "
            f"às normas previstas no Estatuto dos Servidores Públicos do {_esc(municipio_nome)}.",
            styles["clause"],
        )
    )
    story.append(
        Paragraph(
            "<b>PARÁGRAFO PRIMEIRO</b> – O CONTRATADO assume exclusiva responsabilidade pelo cumprimento de todas as obrigações "
            "decorrentes da execução deste contrato, sejam estas de natureza trabalhistas, previdenciária, civil ou fiscal, "
            "inexistindo solidariedade do CONTRATANTE relativamente a esses encargos, inclusive os que eventualmente advirem de "
            "prejuízos causados a terceiros.",
            styles["clause"],
        )
    )
    story.append(
        Paragraph(
            "<b>PARÁGRAFO SEGUNDO</b> – O CONTRATADO assumirá inteira responsabilidade por todos os prejuízos que venha, "
            "dolosa ou culposamente, causar ao Município quando da prestação dos serviços.",
            styles["clause"],
        )
    )
    story.append(
        Paragraph(
            "<b>PARÁGRAFO TERCEIRO</b> – O CONTRATADO prestará todos os esclarecimentos que forem solicitados pelo Município, "
            "cujas reclamações se obriga a atender, prontamente.",
            styles["clause"],
        )
    )
    story.append(
        Paragraph(
            "<b>PARÁGRAFO QUARTO</b> – No caso de recusa no atendimento de qualquer reclamação, independentemente das sanções "
            "cabíveis, o Município poderá confiar a outrem a prestação dos serviços não executados, notificando brevemente ao "
            "CONTRATADO, descontando o seu custo de uma só vez, no primeiro pagamento subsequente ou no valor da garantia, "
            "sem que a mesma possa impugnar seu valor.",
            styles["clause"],
        )
    )

    # PÁGINA 4 (Foro, Data, Assinaturas e Testemunhas)
    story.append(PageBreak())
    t4 = _timbre_flowable(timbre_path)
    if t4:
        story.append(t4)
        story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("12 – DO FORO", styles["heading"]))
    story.append(
        Paragraph(
            f"<b>CLÁUSULA DÉCIMA SEGUNDA</b> – Fica eleito o FORO da Comarca de {_esc(municipio_cidade)} – {_esc(municipio_uf)}, "
            f"com expressa renúncia de qualquer outro, para serem dirimidas quaisquer dúvidas pertinentes ao presente contrato.",
            styles["clause"],
        )
    )
    story.append(
        Paragraph(
            "As partes firmam o presente instrumento em igual teor e forma, obrigando-se por si e seus sucessores ao fiel "
            "cumprimento do que ora ficou ajustado.",
            styles["clause"],
        )
    )

    story.append(Spacer(1, 5 * mm))
    story.append(
        Paragraph(
            f"{_esc(municipio_cidade)}/{_esc(municipio_uf)}, {_esc(contrato.get('dt_assinatura_extenso') or '')}.",
            styles["center_bold"],
        )
    )
    story.append(Spacer(1, 8 * mm))

    # Bloco de assinaturas (Contratante com assinatura fixa da Secretaria quando configurada)
    sig_blocks: List[Any] = []
    img_sec = _assinatura_img_flowable(contrato.get("assinatura_secretaria_b64"), max_w_mm=58.0, max_h_mm=18.0)
    if img_sec:
        sig_blocks.append(img_sec)
        sig_blocks.append(Spacer(1, -2 * mm))
    sig_blocks.extend(
        [
            Paragraph("____________________________________________________________", styles["center"]),
            Paragraph(f"<b>{_esc(municipio_nome)} – {_esc(secretaria_nome)}</b>", styles["center"]),
            Paragraph(f"{_esc(contrato.get('representante_nome') or '')} — {_esc(rep_cargo)}", styles["center"]),
            Spacer(1, 7 * mm),
        ]
    )

    local_cfg = (selo_eletronico or {}).get("local_assinatura") or {}
    modo_local = str(local_cfg.get("modo") or "BLOCO_CONTRATADO").upper()

    def _criar_tabela_selo(selo_dict):
        qr_img = Image(io.BytesIO(gerar_qrcode_png_bytes(selo_dict.get("validar_url", ""))), width=23 * mm, height=23 * mm)
        selo_texto = (
            f"<b><font color='#0B3D2E'>ASSINADO ELETRONICAMENTE — GESTOOR SIGN</font></b><br/>"
            f"<b>Contratado(a):</b> {_esc(selo_dict.get('servidor_nome'))} • "
            f"<b>CPF:</b> {_esc(selo_dict.get('servidor_cpf_mascarado'))}<br/>"
            f"<b>Modalidade:</b> Assinatura Eletrônica Simples (OTP SMS Presencial — Lei nº 14.063/2020)<br/>"
            f"<b>Data/Hora:</b> {_esc(selo_dict.get('assinado_em_brt'))} (Horário de Brasília)<br/>"
            f"<b>Código de Validação:</b> <font name='Courier'>{_esc(selo_dict.get('codigo_validacao'))}</font><br/>"
            f"<b>Conduzido presencialmente por:</b> {_esc(selo_dict.get('tecnico_nome'))}"
        )
        tbl = Table(
            [[Paragraph(selo_texto, styles["ev_val"]), qr_img]],
            colWidths=[145 * mm, 29 * mm],
        )
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), COR_VERDE_CLARO_BG),
                    ("BOX", (0, 0), (-1, -1), 1.2, COR_VERDE_VIVO),
                    ("LINEBEFORE", (0, 0), (0, -1), 4, COR_VERDE_ESCURO),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (1, 0), (1, 0), "CENTER"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return tbl

    if selo_eletronico and modo_local != "POSICAO_PERSONALIZADA":
        sig_blocks.append(_criar_tabela_selo(selo_eletronico))
    else:
        sig_blocks.extend(
            [
                Paragraph("____________________________________________________________", styles["center"]),
                Paragraph(f"<b>CONTRATADO(A): {_esc(contrato.get('contratado_nome') or '')}</b>", styles["center"]),
                Paragraph(f"CPF: {_esc(contrato.get('contratado_cpf') or '')}", styles["center"]),
            ]
        )

    story.append(KeepTogether(sig_blocks))

    # Testemunhas (com assinaturas, nomes e CPFs fixos quando configurados no município)
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("<b>Testemunhas:</b>", styles["clause"]))

    def _bloco_testemunha(nome_t: str, cpf_t: str, img_b64: Optional[str]) -> List[Any]:
        itens: List[Any] = []
        img_t = _assinatura_img_flowable(img_b64, max_w_mm=44.0, max_h_mm=13.0)
        if img_t:
            itens.append(img_t)
        else:
            itens.append(Spacer(1, 10 * mm))
        itens.append(Paragraph("___________________________________", styles["center"]))
        nome_txt = _esc(nome_t) if nome_t else "_____________________________"
        cpf_txt = _esc(cpf_t) if cpf_t else "_____________________"
        itens.append(Paragraph(f"<b>Nome:</b> {nome_txt}", styles["center"]))
        itens.append(Paragraph(f"<b>CPF:</b> {cpf_txt}", styles["center"]))
        return itens

    col_t1 = _bloco_testemunha(
        (contrato.get("testemunha1_nome") or "").strip(),
        (contrato.get("testemunha1_cpf") or "").strip(),
        contrato.get("testemunha1_assinatura_b64"),
    )
    col_t2 = _bloco_testemunha(
        (contrato.get("testemunha2_nome") or "").strip(),
        (contrato.get("testemunha2_cpf") or "").strip(),
        contrato.get("testemunha2_assinatura_b64"),
    )
    tbl_testemunhas = Table([[col_t1, col_t2]], colWidths=[87 * mm, 87 * mm])
    tbl_testemunhas.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    story.append(KeepTogether([tbl_testemunhas]))

    # PÁGINA 5: EXTRATO DO CONTRATO
    story.append(PageBreak())
    if timbre:
        timbre2 = _timbre_flowable(timbre_path)
        if timbre2:
            story.append(timbre2)
            story.append(Spacer(1, 6 * mm))

    story.append(
        Paragraph(
            f"{_esc(municipio_nome.upper())} – {_esc(secretaria_nome.upper())}<br/>EXTRATO DE CONTRATO Nº {_esc(num_contrato)}{_esc(versao_txt)}",
            styles["title"],
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(
        Paragraph(
            f"<b>CONTRATANTE:</b> {_esc(municipio_nome)} – {_esc(secretaria_nome)}. "
            f"<b>CONTRATADO:</b> {_esc(contrato.get('contratado_nome') or '')}. "
            f"<b>OBJETO:</b> Prestação de serviços na função de {_esc(contrato.get('funcao_nome') or '')}, atendidas as determinações da {_esc(secretaria_nome)}. "
            f"<b>RECURSOS:</b> Orçamento Anual do Município do exercício de {_esc(contrato.get('ano_exercicio') or '')}. "
            f"<b>VALOR:</b> {_esc(contrato.get('remuneracao_formatada') or 'R$0,00')} ({_esc(contrato.get('remuneracao_extenso') or '')}) mensais. "
            f"<b>VIGÊNCIA:</b> {_esc(contrato.get('dt_inicio_formatada') or '')} a {_esc(contrato.get('dt_termino_formatada') or '')}. "
            f"<b>DATA DA ASSINATURA:</b> {_esc(contrato.get('dt_assinatura_formatada') or '')}.",
            styles["clause"],
        )
    )

    if selo_eletronico and modo_local == "BLOCO_CONTRATADO_E_EXTRATO":
        story.append(Spacer(1, 10 * mm))
        story.append(_criar_tabela_selo(selo_eletronico))

    return story


def _montar_relatorio_evidencias_story(
    contrato: Dict[str, Any],
    evidencia: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
) -> List[Any]:
    story: List[Any] = []

    # Cabeçalho Institucional Verde-Escuro Gestoor Sign
    banner_tbl = Table(
        [
            [
                Paragraph("GESTOOR SIGN — RELATÓRIO OFICIAL DE EVIDÊNCIAS", styles["ev_banner_title"]),
                Paragraph(
                    f"<b>CÓDIGO DE AUTENTICIDADE</b><br/><font name='Courier' color='#FACC15'>{_esc(evidencia.get('codigo_validacao'))}</font>",
                    ParagraphStyle(
                        "EvCodeRight",
                        parent=styles["ev_banner_sub"],
                        alignment=TA_RIGHT,
                        textColor=colors.white,
                    ),
                ),
            ],
            [
                Paragraph(
                    f"Assinatura Eletrônica Presencial com Autenticação OTP SMS • {_esc(contrato.get('municipio_nome') or 'Município')} / {_esc(contrato.get('secretaria_nome') or '')}",
                    styles["ev_banner_sub"],
                ),
                Paragraph(
                    f"Status: <font color='#4ADE80'><b>{_esc(evidencia.get('status_label') or 'ASSINADO ELETRONICAMENTE')}</b></font>",
                    ParagraphStyle("EvStatRight", parent=styles["ev_banner_sub"], alignment=TA_RIGHT),
                ),
            ],
        ],
        colWidths=[116 * mm, 58 * mm],
    )
    banner_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), COR_VERDE_ESCURO),
                ("LINEBELOW", (0, 1), (-1, 1), 3, COR_AMARELO),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(banner_tbl)
    story.append(Spacer(1, 4 * mm))

    # 1. Identificação do Contrato e do Servidor
    story.append(Paragraph("1. IDENTIFICAÇÃO DO CONTRATO E DO SIGNATÁRIO", styles["ev_sec"]))
    dados_gerais = [
        [
            Paragraph("<b>Nº do Contrato / Versão</b>", styles["ev_label"]),
            Paragraph(f"{_esc(contrato.get('num_contrato'))} — Versão {_esc(contrato.get('versao', 1))}", styles["ev_val"]),
            Paragraph("<b>Exercício / Tipo</b>", styles["ev_label"]),
            Paragraph(f"{_esc(contrato.get('ano_exercicio'))} • {_esc(contrato.get('tipo_contrato') or 'TEMPORARIO')}", styles["ev_val"]),
        ],
        [
            Paragraph("<b>Servidor Signatário</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("servidor_nome")), styles["ev_val"]),
            Paragraph("<b>CPF (LGPD)</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("servidor_cpf_mascarado")), styles["ev_val"]),
        ],
        [
            Paragraph("<b>Telefone SMS Utilizado</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("telefone_mascarado")), styles["ev_val"]),
            Paragraph("<b>Técnico do RH Condutor</b>", styles["ev_label"]),
            Paragraph(f"{_esc(evidencia.get('tecnico_nome'))} ({_esc(evidencia.get('tecnico_username'))})", styles["ev_val"]),
        ],
        [
            Paragraph("<b>Modalidade Jurídica</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("modalidade_label") or "Assinatura Eletrônica Simples (Lei nº 14.063/2020, art. 4º, I)"), styles["ev_val"]),
            Paragraph("<b>Referência Normativa</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("ato_normativo") or "Lei nº 14.063/2020 • MP nº 2.200-2/2001 • LGPD (Lei nº 13.709/2018)"), styles["ev_val"]),
        ],
        [
            Paragraph("<b>Local da Assinatura</b>", styles["ev_label"]),
            Paragraph(_esc(((evidencia.get("local_assinatura") or {}).get("descricao")) or "Folha de Assinaturas — Campo do Contratado (Pág. 4)"), styles["ev_val"]),
            Paragraph("<b>Ambiente / Modalidade</b>", styles["ev_label"]),
            Paragraph("Presencial no Setor de RH (Gestoor360)", styles["ev_val"]),
        ],
    ]
    tbl_gerais = Table(dados_gerais, colWidths=[34 * mm, 56 * mm, 34 * mm, 50 * mm])
    tbl_gerais.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, COR_BORDA),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F8FAFC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(tbl_gerais)

    # 2. Marcos Temporais e Autenticação SMS
    story.append(Paragraph("2. MARCOS TEMPORAIS E AUTENTICAÇÃO POR SMS", styles["ev_sec"]))
    dados_tempo = [
        [
            Paragraph("<b>Geração do Contrato</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("data_geracao_brt")), styles["ev_val"]),
            Paragraph("<b>Conferência Presencial</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("contrato_conferido_brt")), styles["ev_val"]),
        ],
        [
            Paragraph("<b>Envio do Código SMS</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("sms_enviado_brt")), styles["ev_val"]),
            Paragraph("<b>Validação do Código SMS</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("sms_validado_brt")), styles["ev_val"]),
        ],
        [
            Paragraph("<b>Manifestação de Vontade</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("manifestacao_brt")), styles["ev_val"]),
            Paragraph("<b>Selagem / Assinatura Final</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("assinado_em_brt")), styles["ev_val"]),
        ],
        [
            Paragraph("<b>Provedor / Protocolo SMS</b>", styles["ev_label"]),
            Paragraph(f"{_esc((evidencia.get('sms_provider') or '').upper())} • ID: {_esc(evidencia.get('sms_message_id') or 'N/A')}", styles["ev_val"]),
            Paragraph("<b>Fuso de Referência</b>", styles["ev_label"]),
            Paragraph("America/Sao_Paulo (BRT / UTC-03:00)", styles["ev_val"]),
        ],
    ]
    tbl_tempo = Table(dados_tempo, colWidths=[36 * mm, 51 * mm, 36 * mm, 51 * mm])
    tbl_tempo.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, COR_BORDA),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F8FAFC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(tbl_tempo)

    # 3. Manifestação Expressa de Vontade
    story.append(Paragraph("3. REGISTRO DA MANIFESTAÇÃO EXPRESSA DE VONTADE", styles["ev_sec"]))
    termo_box = Table(
        [
            [
                Paragraph(
                    f"“{_esc(evidencia.get('termo_manifestacao_texto'))}”<br/><br/>"
                    f"<font size='7.5' color='#065F46'><b>Confirmação realizada diretamente pelo servidor em {_esc(evidencia.get('manifestacao_brt'))} "
                    f"({ _esc(evidencia.get('metodo_confirmacao_servidor') or 'ACEITE_EXPRESSO_PRESENCIAL') }).</b></font>",
                    styles["ev_quote"],
                )
            ]
        ],
        colWidths=[174 * mm],
    )
    termo_box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), COR_VERDE_CLARO_BG),
                ("BOX", (0, 0), (-1, -1), 0.8, COR_VERDE_VIVO),
                ("LINEBEFORE", (0, 0), (0, -1), 3.5, COR_VERDE_ESCURO),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(termo_box)

    # 4. Integridade Criptográfica e QR Code de Autenticidade
    story.append(Paragraph("4. INTEGRIDADE CRIPTOGRÁFICA (SHA-256) E VERIFICAÇÃO PÚBLICA", styles["ev_sec"]))
    qr_png = gerar_qrcode_png_bytes(evidencia.get("validar_url", ""))
    qr_img = Image(io.BytesIO(qr_png), width=28 * mm, height=28 * mm)
    hash_info = (
        f"<b>Hash SHA-256 do Contrato Base (versão conferida):</b><br/>"
        f"<font name='Courier' size='7.2'>{_esc(evidencia.get('hash_contrato_base_sha256'))}</font><br/><br/>"
        f"<b>Hash SHA-256 do Pacote Canônico de Evidências:</b><br/>"
        f"<font name='Courier' size='7.2'>{_esc(evidencia.get('hash_evidencias_sha256'))}</font><br/><br/>"
        f"<b>Código Único de Validação:</b> <font name='Courier'><b>{_esc(evidencia.get('codigo_validacao'))}</b></font><br/>"
        f"<b>URL de Verificação:</b> <font size='7.5'>{_esc(evidencia.get('validar_url'))}</font><br/>"
        f"<font size='7' color='#4B5563'>Escaneie o QR Code ou acesse a URL acima para conferir a autenticidade e o status vigente desta versão contratual.</font>"
    )
    tbl_hash = Table([[Paragraph(hash_info, styles["ev_val"]), qr_img]], colWidths=[140 * mm, 34 * mm])
    tbl_hash.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.8, COR_VERDE_ESCURO),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(tbl_hash)

    # 5. Informações Técnicas da Sessão
    story.append(Paragraph("5. INFORMAÇÕES TÉCNICAS DA SESSÃO PRESENCIAL", styles["ev_sec"]))
    dados_tec = [
        [
            Paragraph("<b>Endereço IP (Estação RH)</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("ip_origem") or "N/D"), styles["ev_val"]),
            Paragraph("<b>Impressão da Sessão</b>", styles["ev_label"]),
            Paragraph(_esc(evidencia.get("session_fingerprint") or "N/D"), styles["ev_mono"]),
        ],
        [
            Paragraph("<b>Agente / Navegador</b>", styles["ev_label"]),
            Paragraph(_esc((evidencia.get("user_agent") or "N/D")[:160]), styles["ev_small"]),
            Paragraph("<b>Estação / Fluxo</b>", styles["ev_label"]),
            Paragraph("Presencial no RH — Gestoor360", styles["ev_val"]),
        ],
    ]
    tbl_tec = Table(dados_tec, colWidths=[34 * mm, 64 * mm, 30 * mm, 46 * mm])
    tbl_tec.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, COR_BORDA),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F8FAFC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(tbl_tec)

    # 6. Histórico Cronológico de Eventos (Hash Chain)
    story.append(Paragraph("6. HISTÓRICO CRONOLÓGICO DE EVENTOS (TRILHA AUDITÁVEL)", styles["ev_sec"]))
    ev_rows = [
        [
            Paragraph("<b>Data/Hora (BRT)</b>", styles["ev_label"]),
            Paragraph("<b>Evento</b>", styles["ev_label"]),
            Paragraph("<b>Ator</b>", styles["ev_label"]),
            Paragraph("<b>Descrição / Hash Encadeado</b>", styles["ev_label"]),
        ]
    ]
    for ev in evidencia.get("eventos") or []:
        h_curto = (ev.get("hash_evento_atual") or "")[:16]
        desc_html = f"{_esc(ev.get('descricao'))}"
        if h_curto:
            desc_html += f"<br/><font name='Courier' size='6.5' color='#6B7280'>chain:{_esc(h_curto)}...</font>"
        ev_rows.append(
            [
                Paragraph(_esc(ev.get("data_hora_brt")), styles["ev_small"]),
                Paragraph(f"<b>{_esc(ev.get('tipo_evento'))}</b>", styles["ev_small"]),
                Paragraph(_esc(ev.get("ator_tipo")), styles["ev_small"]),
                Paragraph(desc_html, styles["ev_small"]),
            ]
        )

    tbl_ev = Table(ev_rows, colWidths=[29 * mm, 36 * mm, 22 * mm, 87 * mm], repeatRows=1)
    tbl_ev.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, COR_BORDA),
                ("BACKGROUND", (0, 0), (-1, 0), COR_VERDE_CLARO_BG),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(tbl_ev)

    story.append(Spacer(1, 4 * mm))
    aviso_legal = Table(
        [
            [
                Paragraph(
                    "<b>NOTA DE CONFORMIDADE LEGAL:</b> Este documento foi assinado eletronicamente de forma presencial "
                    "na modalidade <b>Assinatura Eletrônica Simples</b>, nos termos da Lei nº 14.063/2020 (art. 4º, I), "
                    "da Medida Provisória nº 2.200-2/2001 (art. 10, § 2º) e em observância à LGPD (Lei nº 13.709/2018). "
                    "Qualquer alteração posterior no conteúdo contratual invalida esta versão, exigindo geração de nova versão "
                    "e novo procedimento completo de assinatura.",
                    styles["ev_small"],
                )
            ]
        ],
        colWidths=[174 * mm],
    )
    aviso_legal.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), COR_AMARELO_BG),
                ("BOX", (0, 0), (-1, -1), 0.7, COR_AMARELO),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(aviso_legal)
    return story


def gerar_pdf_contrato_base(contrato: Dict[str, Any], timbre_path: Optional[str] = None) -> Tuple[bytes, str]:
    """Gera o PDF oficial da versão exata do contrato antes da assinatura e retorna (bytes, sha256)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=14 * mm,
        bottomMargin=18 * mm,
        title=f"Contrato {contrato.get('num_contrato')} v{contrato.get('versao', 1)}",
        author="Gestoor360 - Gestoor Sign",
    )
    styles = _build_styles()
    story = _montar_corpo_contrato_story(contrato, styles, timbre_path, selo_eletronico=None)
    rodape = f"Gestoor360 • Contrato Nº {contrato.get('num_contrato')} (Versão {contrato.get('versao', 1)}) • Documento Base para Assinatura Presencial"
    doc.build(
        story,
        onFirstPage=lambda c, d: _draw_page_footer(c, d, rodape, selo_eletronico=None),
        onLaterPages=lambda c, d: _draw_page_footer(c, d, rodape, selo_eletronico=None),
    )
    raw = buf.getvalue()
    return raw, sha256_bytes(raw)


def gerar_pdf_contrato_assinado(
    contrato: Dict[str, Any],
    evidencia: Dict[str, Any],
    timbre_path: Optional[str] = None,
) -> Tuple[bytes, str]:
    """Gera o PDF Final Assinado Eletronicamente (Contrato + Selo + Relatório de Evidências + QR Code) e retorna (bytes, sha256)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=14 * mm,
        bottomMargin=18 * mm,
        title=f"Contrato Assinado {contrato.get('num_contrato')} v{contrato.get('versao', 1)} - Gestoor Sign",
        author="Gestoor360 - Gestoor Sign",
    )
    styles = _build_styles()
    story = _montar_corpo_contrato_story(contrato, styles, timbre_path, selo_eletronico=evidencia)
    story.append(PageBreak())
    story.extend(_montar_relatorio_evidencias_story(contrato, evidencia, styles))

    rodape = (
        f"GESTOOR SIGN • Contrato Nº {contrato.get('num_contrato')} (v{contrato.get('versao', 1)}) • "
        f"Código: {evidencia.get('codigo_validacao')} • Assinatura Eletrônica Simples"
    )
    doc.build(
        story,
        onFirstPage=lambda c, d: _draw_page_footer(c, d, rodape, selo_eletronico=evidencia, total_paginas_contrato=5),
        onLaterPages=lambda c, d: _draw_page_footer(c, d, rodape, selo_eletronico=evidencia, total_paginas_contrato=5),
    )
    raw = buf.getvalue()
    return raw, sha256_bytes(raw)


def gerar_pdf_relatorio_evidencias(
    contrato: Dict[str, Any],
    evidencia: Dict[str, Any],
) -> Tuple[bytes, str]:
    """Gera o PDF autônomo do Relatório de Evidências do Gestoor Sign e retorna (bytes, sha256)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=14 * mm,
        bottomMargin=18 * mm,
        title=f"Relatório de Evidências - Contrato {contrato.get('num_contrato')}",
        author="Gestoor360 - Gestoor Sign",
    )
    styles = _build_styles()
    story = _montar_relatorio_evidencias_story(contrato, evidencia, styles)
    rodape = f"GESTOOR SIGN • Relatório de Evidências • Código: {evidencia.get('codigo_validacao')}"
    doc.build(
        story,
        onFirstPage=lambda c, d: _draw_page_footer(c, d, rodape, selo_eletronico=None),
        onLaterPages=lambda c, d: _draw_page_footer(c, d, rodape, selo_eletronico=None),
    )
    raw = buf.getvalue()
    return raw, sha256_bytes(raw)
