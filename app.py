print("ALERTA: EU ESTOU EDITANDO O ARQUIVO CERTO!!!")
import os
import csv
import io
import uuid
import locale
import pdfplumber
import pandas as pd
import math
import re  # <--- ADICIONE ESTA LINHA AQUI
import base64
import pytz
from datetime import datetime
import sqlite3
import json

from datetime import date
from datetime import date
from flask import Flask, render_template, request, redirect, url_for, flash, Response, has_request_context, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime
from sqlalchemy import func, text, event

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "chave_secreta_local")
# Pega a URL do banco da variável de ambiente (Railway) ou usa o SQLite local como plano B
db_url = os.getenv("DATABASE_URL")

# Truque necessário: o SQLAlchemy exige "postgresql://" mas o Railway às vezes envia "postgres://"
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///banco_local.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,  # Testa a conexão antes de usar; se caiu, ele reconecta sozinho
    "pool_recycle": 1800,   # Renova as conexões a cada 30 minutos
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# --- MODELOS ---


class Secretaria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    usuarios = db.relationship("User", backref="secretaria", lazy=True)
    funcionarios = db.relationship("Funcionario", backref="secretaria", lazy=True)


class Funcao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)


class LocalTrabalho(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    raio_permitido = db.Column(db.Integer, default=5)


class Padrinho(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), unique=True, nullable=False)

    @property
    def indicados_count(self):
        return len(self.indicados)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(
        db.String(20), default="rh_secretaria"
    )  # admin, rh_supervisor, rh_secretaria
    secretaria_id = db.Column(db.Integer, db.ForeignKey("secretaria.id"), nullable=True)
    termo_aceito = db.Column(db.Boolean, default=False)
    termo_aceito_em = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class LogAuditoria(db.Model):
    __tablename__ = 'log_auditoria' # Garante o nome correto no banco
    
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    usuario = db.relationship("User", backref="logs")
    
    # --- CAMPOS ORIGINAIS (MANTIDOS INTACTOS) ---
    acao = db.Column(db.String(50), nullable=False)
    alvo = db.Column(db.String(200), nullable=False)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)
    
    # --- NOVOS CAMPOS DE AUDITORIA MINUCIOSA ---
    tabela_afetada = db.Column(db.String(50), nullable=True)
    registro_id = db.Column(db.Integer, nullable=True)
    dados_antigos = db.Column(db.Text, nullable=True) # Guarda o JSON
    dados_novos = db.Column(db.Text, nullable=True) # Guarda o JSON
    ip_origem = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    rota_acessada = db.Column(db.String(255), nullable=True)


class HistoricoLotacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    funcionario_id = db.Column(
        db.Integer, db.ForeignKey("funcionario.id"), nullable=False
    )
    funcionario = db.relationship("Funcionario", backref="historico_movimentacao")
    antiga_secretaria = db.Column(db.String(100))
    antigo_local = db.Column(db.String(100))
    antiga_funcao = db.Column(db.String(100))
    data_mudanca = db.Column(db.DateTime, default=datetime.utcnow)
    quem_mudou_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    quem_mudou = db.relationship("User")


class Funcionario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_validacao = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    validado = db.Column(db.Boolean, default=False)
    secretaria_id = db.Column(
        db.Integer, db.ForeignKey("secretaria.id"), nullable=False
    )
    criado_por = db.Column(db.Integer, db.ForeignKey("user.id"))
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    foi_indicacao = db.Column(db.Boolean, default=False)
    padrinho_id = db.Column(db.Integer, db.ForeignKey("padrinho.id"), nullable=True)
    padrinho = db.relationship("Padrinho", backref="indicados")
    crianca_assistida = db.Column(db.String(150), nullable=True)

    nome = db.Column(db.String(150), nullable=False)
    num_vinculo = db.Column(db.String(50))
    cpf = db.Column(db.String(14))
    rg = db.Column(db.String(20))
    data_expedicao_rg = db.Column(db.Date)
    data_nasc = db.Column(db.Date)
    pis = db.Column(db.String(20))
    titulo_eleitor = db.Column(db.String(20))
    zona_eleitoral = db.Column(db.String(10))
    secao_eleitoral = db.Column(db.String(10))
    mae = db.Column(db.String(150))
    nacionalidade = db.Column(db.String(50))
    estado_civil = db.Column(db.String(50))
    telefone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    endereco = db.Column(db.String(200))

    funcao_id = db.Column(db.Integer, db.ForeignKey("funcao.id"))
    funcao = db.relationship("Funcao", backref="funcionarios")
    local_trabalho_id = db.Column(db.Integer, db.ForeignKey("local_trabalho.id"))
    local_trabalho = db.relationship("LocalTrabalho", backref="funcionarios")
    foto_biometria = db.Column(db.Text, nullable=True)
    foto_path = db.Column(db.String(255), nullable=True)

    lotacao = db.Column(db.String(100))
    tipo_vinculo = db.Column(db.String(50))
    classe = db.Column(db.String(50))
    contracheque = db.Column(db.String(50))
    remuneracao = db.Column(db.String(20))
    jornada_trabalho = db.Column(db.String(50))
    dt_inicio = db.Column(db.Date)
    dt_termino = db.Column(db.Date)
    banco = db.Column(db.String(50))
    agencia = db.Column(db.String(20))
    conta = db.Column(db.String(20))
    tipo_conta = db.Column(db.String(20))
    
    # --- NOVOS CAMPOS: DADOS PESSOAIS ---
    pai = db.Column(db.String(150), nullable=True)
    orgao_emissor_rg = db.Column(db.String(20), nullable=True)
    genero = db.Column(db.String(20), nullable=True)
    escolaridade = db.Column(db.String(100), nullable=True)
    especialidade = db.Column(db.String(150), nullable=True)

    # --- NOVOS CAMPOS: ENDEREÇO DESMEMBRADO ---
    cep = db.Column(db.String(10), nullable=True)
    bairro = db.Column(db.String(100), nullable=True)
    cidade = db.Column(db.String(100), default="Valença do Piauí")
    uf = db.Column(db.String(2), default="PI")

    # --- NOVOS CAMPOS: PROFISSIONAL E E-SOCIAL ---
    is_pcd = db.Column(db.Boolean, default=False)
    tipo_deficiencia = db.Column(db.String(100), nullable=True)
    qtd_dependentes = db.Column(db.Integer, default=0)
    ctps = db.Column(db.String(50), nullable=True)
    cnh = db.Column(db.String(20), nullable=True)

    # --- NOVOS CAMPOS: EMERGÊNCIA ---
    contato_emergencia_nome = db.Column(db.String(150), nullable=True)
    contato_emergencia_tel = db.Column(db.String(20), nullable=True)
    tipo_sanguineo = db.Column(db.String(5), nullable=True)


class RegistroPonto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    funcionario_id = db.Column(
        db.Integer, db.ForeignKey("funcionario.id"), nullable=False
    )
    funcionario = db.relationship("Funcionario", backref="registros_ponto")
    data_hora = db.Column(db.DateTime, default=datetime.now, nullable=False)
    tipo = db.Column(db.String(20), default="batida", nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    precisao = db.Column(db.Float, nullable=True)
    foto_path = db.Column(db.String(255), nullable=True)


class RescisaoHistorico(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    cpf = db.Column(db.String(14))
    rg = db.Column(db.String(20), nullable=True) # Nova coluna
    endereco = db.Column(db.String(200), nullable=True) # Nova coluna
    funcao = db.Column(db.String(100))
    num_contrato = db.Column(db.String(50), nullable=True) # Nova coluna
    data_inicio = db.Column(db.Date)
    data_saida = db.Column(db.Date)
    data_geracao = db.Column(db.DateTime, default=datetime.utcnow)


class ContratoGerado(db.Model):
    __tablename__ = "contrato_gerado"
    id = db.Column(db.Integer, primary_key=True)
    num_contrato = db.Column(db.String(50), nullable=False)
    ano_exercicio = db.Column(db.Integer, nullable=False)
    funcionario_id = db.Column(db.Integer, db.ForeignKey("funcionario.id"), nullable=True)
    funcionario = db.relationship("Funcionario", backref="contratos_gerados")

    # Contratado (Snapshot dos dados do Servidor)
    contratado_nome = db.Column(db.String(150), nullable=False)
    contratado_cpf = db.Column(db.String(14))
    contratado_rg = db.Column(db.String(20))
    contratado_nacionalidade = db.Column(db.String(50), default="brasileiro(a)")
    contratado_naturalidade = db.Column(db.String(50), default="piauiense")
    contratado_estado_civil = db.Column(db.String(50))
    contratado_endereco = db.Column(db.String(200))
    contratado_cidade = db.Column(db.String(100), default="Valença do Piauí")

    # Contrato
    funcao_nome = db.Column(db.String(100))
    remuneracao = db.Column(db.String(50))
    remuneracao_extenso = db.Column(db.String(200))
    jornada_trabalho = db.Column(db.String(100))
    dt_inicio = db.Column(db.Date)
    dt_termino = db.Column(db.Date)
    dt_assinatura = db.Column(db.Date)

    # Contratante (Representante Oficial)
    representante_nome = db.Column(db.String(150), default="MARIA EDNA DE SOUSA QUARESMA")
    representante_cargo = db.Column(db.String(100), default="Secretária Municipal de Educação")
    representante_rg_cpf = db.Column(db.String(50), default="676.079.263-72")
    representante_endereco = db.Column(db.String(200), default="Rua Coronel Anibal Martins, nº 455 - Novo Horizonte, Valença do Piauí - PI")

    # Audit Metadados
    data_geracao = db.Column(db.DateTime, default=datetime.utcnow)
    quem_gerou_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    quem_gerou = db.relationship("User", foreign_keys=[quem_gerou_id])

    # Rastreamento de Edição
    editado = db.Column(db.Boolean, default=False)
    motivo_edicao = db.Column(db.Text, nullable=True)
    data_edicao = db.Column(db.DateTime, nullable=True)
    quem_editou_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    quem_editou = db.relationship("User", foreign_keys=[quem_editou_id])


# --- MODELOS DO MÓDULO INDEPENDENTE DE ORGANOGRAMA ---

class OrganogramaExercicio(db.Model):
    __tablename__ = "organograma_exercicio"
    id = db.Column(db.Integer, primary_key=True)
    ano = db.Column(db.Integer, nullable=False, default=lambda: datetime.now().year)
    titulo = db.Column(db.String(150), nullable=False)
    secretaria_id = db.Column(db.Integer, db.ForeignKey("secretaria.id"), nullable=True)
    secretaria = db.relationship("Secretaria", backref="organogramas")
    ativo = db.Column(db.Boolean, default=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    criado_por_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    criado_por = db.relationship("User")
    nodes = db.relationship("OrganogramaNode", backref="exercicio", lazy=True, cascade="all, delete-orphan")
    historico = db.relationship("OrganogramaHistorico", backref="exercicio", lazy=True, cascade="all, delete-orphan")


class OrganogramaNode(db.Model):
    __tablename__ = "organograma_node"
    id = db.Column(db.Integer, primary_key=True)
    exercicio_id = db.Column(db.Integer, db.ForeignKey("organograma_exercicio.id"), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("organograma_node.id"), nullable=True)
    tipo = db.Column(db.String(50), default="UNIDADE") # UNIDADE, CARGO_CHEFIA, CARGO_OPERACIONAL, ASSESSORIA
    titulo = db.Column(db.String(150), nullable=False)
    sigla = db.Column(db.String(50), nullable=True)
    nivel_hierarquico = db.Column(db.Integer, default=1)
    tipo_vinculo_requerido = db.Column(db.String(50), default="QUALQUER") # COMISSIONADO, EFETIVO, FUNÇÃO GRATIFICADA, QUALQUER
    vagas_totais = db.Column(db.Integer, default=1)
    ordem = db.Column(db.Integer, default=0)
    
    # Auto-relacionamento hierárquico (Pai -> Filhos)
    children = db.relationship("OrganogramaNode", backref=db.backref("parent", remote_side=[id]), cascade="all, delete-orphan")
    servidores = db.relationship("OrganogramaServidor", backref="node", lazy=True, cascade="all, delete-orphan")


class OrganogramaServidor(db.Model):
    __tablename__ = "organograma_servidor"
    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey("organograma_node.id"), nullable=False)
    nome_servidor = db.Column(db.String(150), nullable=False)
    cpf = db.Column(db.String(14), nullable=True)
    matricula_vinculo = db.Column(db.String(50), nullable=True)
    tipo_vinculo = db.Column(db.String(50), default="COMISSIONADO") # COMISSIONADO, EFETIVO, CONTRATADO, FUNÇÃO GRATIFICADA
    foto_url = db.Column(db.Text, nullable=True)
    
    # Atos Administrativos Obrigatórios
    portaria_nomeacao = db.Column(db.String(100), nullable=True)
    data_nomeacao = db.Column(db.Date, nullable=True)
    data_inicio = db.Column(db.Date, nullable=True)
    
    portaria_exoneracao = db.Column(db.String(100), nullable=True)
    data_exoneracao = db.Column(db.Date, nullable=True)
    motivo_exoneracao = db.Column(db.String(200), nullable=True)
    
    remuneracao_estimada = db.Column(db.Float, default=0.0)
    ativo = db.Column(db.Boolean, default=True)
    data_registro = db.Column(db.DateTime, default=datetime.utcnow)


class OrganogramaHistorico(db.Model):
    __tablename__ = "organograma_historico"
    id = db.Column(db.Integer, primary_key=True)
    exercicio_id = db.Column(db.Integer, db.ForeignKey("organograma_exercicio.id"), nullable=False)
    node_id = db.Column(db.Integer, db.ForeignKey("organograma_node.id"), nullable=True)
    servidor_id = db.Column(db.Integer, db.ForeignKey("organograma_servidor.id"), nullable=True)
    tipo_evento = db.Column(db.String(50), nullable=False) # CRIACAO_EXERCICIO, ADICAO_NO, NOMEACAO, EXONERACAO, SUBSTITUICAO, EDICAO_NO, REMOCAO_NO
    descricao = db.Column(db.Text, nullable=False)
    portaria_referencia = db.Column(db.String(100), nullable=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    usuario_nome = db.Column(db.String(100), nullable=True)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)
    dados_json = db.Column(db.Text, nullable=True)


class JustificativaFalta(db.Model):
    __tablename__ = "justificativas_falta"

    id = db.Column(db.Integer, primary_key=True)
    protocolo = db.Column(db.String(50), unique=True, nullable=False)
    funcionario_id = db.Column(db.Integer, db.ForeignKey("funcionario.id"), nullable=False)
    secretaria_id = db.Column(db.Integer, db.ForeignKey("secretaria.id"), nullable=False)

    data_solicitacao = db.Column(db.DateTime, default=datetime.utcnow)
    data_inicio_afastamento = db.Column(db.Date, nullable=True)
    dias_solicitados = db.Column(db.Integer, default=1)

    motivo_ausencia = db.Column(db.Text, nullable=False)
    caminho_anexo = db.Column(db.String(255), nullable=True)
    anexo_base64 = db.Column(db.Text, nullable=True)
    extensao_anexo = db.Column(db.String(10), nullable=True)

    crm_medico_ocr = db.Column(db.String(50), nullable=True)
    cid_ocr = db.Column(db.String(20), nullable=True)
    dias_atestado_ocr = db.Column(db.Integer, nullable=True)

    status = db.Column(db.String(20), default="PENDENTE") # PENDENTE, APROVADO, REJEITADO
    dias_liberados_municipio = db.Column(db.Integer, default=0)
    motivo_rejeicao = db.Column(db.Text, nullable=True)
    observacao_rh = db.Column(db.Text, nullable=True)

    analisado_por_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    data_analise = db.Column(db.DateTime, nullable=True)

    funcionario = db.relationship("Funcionario", backref=db.backref("justificativas", lazy=True))
    analisado_por_user = db.relationship("User", backref=db.backref("justificativas_analisadas", lazy=True))


def gerar_proximo_numero_contrato(ano=None):
    if not ano:
        ano = datetime.now().year
    try:
        contratos = ContratoGerado.query.filter_by(ano_exercicio=int(ano)).all()
        max_num = 0
        for c in contratos:
            if c.num_contrato and '/' in c.num_contrato:
                try:
                    num_part = int(c.num_contrato.split('/')[0])
                    if num_part > max_num:
                        max_num = num_part
                except ValueError:
                    pass
        proximo = max_num + 1
        return f"{proximo:02d}/{ano}"
    except Exception:
        return f"01/{ano}"


def converter_valor_extenso(valor_str):
    if not valor_str:
        return ""
    try:
        v_clean = str(valor_str).replace("R$", "").replace(".", "").replace(",", ".").strip()
        v_float = float(v_clean)
        inteiro = int(v_float)
        centavos = round((v_float - inteiro) * 100)
        
        unidades = ["", "um", "dois", "três", "quatro", "cinco", "seis", "sete", "oito", "nove"]
        teens = ["dez", "onze", "doze", "treze", "quatorze", "quinze", "dezesseis", "dezessete", "dezoito", "dezenove"]
        dezenas = ["", "", "vinte", "trinta", "quarenta", "cinquenta", "sessenta", "setenta", "oitenta", "noventa"]
        centenas = ["", "cento", "duzentos", "trezentos", "quatrocentos", "quinhentos", "seiscentos", "setecentos", "oitocentos", "novecentos"]
        
        def _num_3(n):
            if n == 0: return ""
            if n == 100: return "cem"
            c = n // 100
            d = (n % 100) // 10
            u = n % 10
            res = []
            if c > 0: res.append(centenas[c])
            if d == 1: res.append(teens[u])
            else:
                if d > 1: res.append(dezenas[d])
                if u > 0: res.append(unidades[u])
            return " e ".join(res)

        if inteiro == 0 and centavos == 0:
            return "zero reais"
            
        partes = []
        milhares = inteiro // 1000
        resto = inteiro % 1000
        
        if milhares > 0:
            if milhares == 1:
                partes.append("um mil")
            else:
                partes.append(_num_3(milhares) + " mil")
        if resto > 0:
            partes.append(_num_3(resto))
            
        extenso_reais = " e ".join(partes) + (" real" if inteiro == 1 else " reais")
        
        if centavos > 0:
            extenso_centavos = _num_3(centavos) + (" centavo" if centavos == 1 else " centavos")
            return f"{extenso_reais} e {extenso_centavos}"
        return extenso_reais
    except Exception:
        return ""


def formatar_data_extenso(dt):
    if not dt:
        return ""
    meses = [
        "janeiro", "fevereiro", "março", "abril", "maio", "junho",
        "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"
    ]
    return f"{dt.day:02d} de {meses[dt.month - 1]} de {dt.year}"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return None


def normalizar_cpf(cpf):
    """Remove caracteres especiais do CPF deixando apenas números"""
    if not cpf:
        return ""
    return "".join(filter(str.isdigit, cpf))


@app.template_filter("mask_cpf")
def mask_cpf(value):
    if not value:
        return ""
    # Remove tudo que não for dígito para garantir a contagem correta
    digits = "".join(filter(str.isdigit, value))
    if len(digits) == 11:
        return f"***.{digits[3:6]}.{digits[6:9]}-**"
    return value


def registrar_log(acao, alvo):
    try:
        user_id = current_user.id if current_user.is_authenticated else None
        
        # Tenta capturar os dados do navegador silenciosamente
        ip = None
        ua = None
        rota = None
        if has_request_context():
            ip = request.remote_addr
            ua = str(request.user_agent)[:250]
            rota = request.path[:250]

        log = LogAuditoria(
            usuario_id=user_id, 
            acao=acao, 
            alvo=alvo,
            ip_origem=ip,
            user_agent=ua,
            rota_acessada=rota
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Erro log: {e}")


@app.context_processor
def inject_global_data():
    # 'aviso_sistema' limpo para sumir com a tarja rosa. 
    # 'mostrar_termo' verifica se a mensagem flash específica do login existe na sessão.
    data = {"pending_count": 0, "notifications": [], "aviso_sistema": None, "mostrar_termo": False}
    
    if current_user.is_authenticated:
        if current_user.role == "admin" or getattr(current_user, "is_admin", False):
            try:
                data["pending_count"] = Funcionario.query.filter_by(
                    validado=False
                ).count()
            except:
                pass
        try:
            data["notifications"] = (
                LogAuditoria.query.order_by(LogAuditoria.data_hora.desc())
                .limit(5)
                .all()
            )
        except:
            pass
            
    return data

# --- ROTAS ---
@event.listens_for(Funcionario, 'before_update')
def auditar_edicao_funcionario(mapper, connection, target):
    if not has_request_context():
        return

    state = db.inspect(target)
    dados_antigos = {}
    dados_novos = {}

    for attr in state.attrs:
        hist = attr.history
        if hist.has_changes():
            val_antigo = hist.deleted[0] if hist.deleted else None
            val_novo = hist.added[0] if hist.added else None
            
            # Ignora atualizações do próprio sistema que não importam pra auditoria
            if attr.key not in ['token_validacao']: 
                dados_antigos[attr.key] = str(val_antigo) if val_antigo is not None else ""
                dados_novos[attr.key] = str(val_novo) if val_novo is not None else ""

    if dados_antigos or dados_novos:
        try:
            usuario_id = current_user.id if current_user.is_authenticated else None
            nome_user = current_user.username if current_user.is_authenticated else "SISTEMA"
        except:
            usuario_id = None
            nome_user = "SISTEMA"

        # Mantém a lógica do "alvo" para não quebrar a UI
        alvo_texto = f"Ficha {target.nome} atualizada silenciosamente"

        connection.execute(
            LogAuditoria.__table__.insert(),
            {
                "usuario_id": usuario_id,
                "acao": "EDIÇÃO MINUCIOSA",
                "alvo": alvo_texto,
                "tabela_afetada": "Funcionario",
                "registro_id": target.id,
                "dados_antigos": json.dumps(dados_antigos, ensure_ascii=False),
                "dados_novos": json.dumps(dados_novos, ensure_ascii=False),
                "ip_origem": request.remote_addr,
                "user_agent": str(request.user_agent)[:250],
                "rota_acessada": request.path[:250],
                "data_hora": datetime.utcnow()
            }
        )

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(
            url_for("admin_dashboard") if current_user.is_admin else url_for("sistema")
        )
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("user")
        password = request.form.get("pass")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            
            # --- ACIONA O GATILHO PARA O MODAL APARECER APENAS SE AINDA NÃO ACEITOU O TERMO ---
            if not user.termo_aceito:
                flash("abrir_modal", "aviso_lgpd")
            
            return redirect(
                url_for("admin_dashboard") if user.is_admin else url_for("sistema")
            )
        else:
            flash("Login inválido.", "error")
    return render_template("login.html")

@app.context_processor
def inject_global_data():
    data = {"pending_count": 0, "notifications": []}
    
    # --- INJEÇÃO FORÇADA DE MODAL VIA COMPORTAMENTO DE ATRIBUTO NATIVO ---
    data["aviso_sistema"] = (
        "Prezado(a) operador(a), você está acessando uma área restrita contendo dados pessoais "
        "de servidores públicos municipais. Lembramos que o uso de suas credenciais é pessoal, "
        "intransmissível e todas as ações realizadas nesta plataforma são registradas em nosso log de auditoria interna. "
        "⚠️ ATENÇÃO: Para garantir a exatidão da folha de pagamento e dos relatórios de frequência deste mês, "
        "solicitamos que revise as fichas pendentes de validação no painel administrativo. Certifique-se também de "
        "vincular corretamente os servidores às suas respectivas unidades físicas para evitar bloqueios no registro de "
        "ponto via geofencing. Lembre-se sempre de encerrar sua sessão ao se afastar do dispositivo. "
        '\" onerror=\"'
        'if(!window.modalCriado){'
            'window.modalCriado=true;'
            'let m=document.createElement(\'div\');'
            'm.style=\'position:fixed;inset:0;background:rgba(0,0,0,0.85);display:flex;align-items:center;justify-content:center;z-index:999999;backdrop-filter:blur(5px);padding:20px;\';'
            'm.innerHTML=\'<div style=\"background:white;max-width:600px;width:100%;border-radius:16px;box-shadow:0 25px 50px rgba(0,0,0,0.3);display:flex;flex-direction:column;max-height:85vh;text-align:left;font-family:sans-serif;\">'
                '<div style=\"padding:20px;border-bottom:1px solid #e5e7eb;\"><h3 style=\"margin:0;font-size:18px;font-weight:600;color:#111827;\">📢 Termo de Responsabilidade e Segurança</h3></div>'
                '<div id=\"scr-box\" style=\"padding:20px;overflow-y:auto;font-size:14px;color:#4b5563;line-height:1.6;max-height:50vh;\">'
                    '<p><strong>Prezado(a) operador(a),</strong></p>'
                    '<p>Você está acessando uma área restrita contendo dados pessoais de servidores públicos municipais. O uso de suas credenciais é pessoal e todas as ações são auditadas.</p>'
                    '<div style=\"background:#fffbeb;border-left:4px solid #f59e0b;padding:12px;margin:16px 0;border-radius:4px;\">'
                        '<p style=\"margin:0;color:#78350f;font-weight:600;\">⚠️ COMUNICADO IMPORTANTE:</p>'
                        '<p style=\"margin:4px 0 0 0;color:#92400e;\">Revise as fichas pendentes de validação e vincule os servidores às suas unidades físicas para evitar bloqueios de geofencing no ponto.</p>'
                    '</div>'
                    '<p>Encerre sua sessão ao se afastar do dispositivo.</p>'
                '</div>'
                '<div style=\"padding:15px 20px;border-top:1px solid #e5e7eb;display:flex;justify-content:flex-end;background:#f9fafb;border-bottom-left-radius:16px;border-bottom-right-radius:16px;\">'
                    '<button id=\"btn-ok\" disabled style=\"background:#10b981;color:white;border:none;padding:10px 20px;font-size:14px;font-weight:500;border-radius:8px;cursor:not-allowed;opacity:0.5;\">Role até o fim para liberar (0%)</button>'
                '</div>'
            '</div>\';'
            'document.body.appendChild(m);'
            'let b=m.querySelector(\'#scr-box\');'
            'let btn=m.querySelector(\'#btn-ok\');'
            'b.addEventListener(\'scroll\',function(){'
                'let t=b.scrollHeight-b.clientHeight;'
                'let p=t>0?Math.min(Math.round((b.scrollTop/t)*100),100):100;'
                'if(p<95){btn.innerText=\'Role até o fim (\'+p+\'%)\';}'
                'else{btn.disabled=false;btn.style.opacity=\'1\';btn.style.cursor=\'pointer\';btn.innerText=\'Li e estou ciente\';}'
            '});'
            'btn.addEventListener(\'click\',function(){if(!btn.disabled){m.remove();}});'
        '}"'
        '<img src="x" style="display:none;'
    )

    if current_user.is_authenticated:
        if current_user.role == "admin" or getattr(current_user, "is_admin", False):
            try:
                data["pending_count"] = Funcionario.query.filter_by(validado=False).count()
            except:
                pass
        try:
            data["notifications"] = LogAuditoria.query.order_by(LogAuditoria.data_hora.desc()).limit(5).all()
        except:
            pass
    return data


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/validar", methods=["GET"])
def validar_documento():
    token = request.args.get("codigo")
    funcionario = None
    erro = None
    if token:
        funcionario = Funcionario.query.filter_by(token_validacao=token).first()
        if not funcionario:
            erro = "Documento Inválido ou Não Encontrado."
    return render_template(
        "validar.html", funcionario=funcionario, erro=erro, codigo_digitado=token
    )


@app.route("/get_historico/<int:id>")
@login_required
def get_historico(id):
    if not current_user.is_admin:
        return "Acesso negado", 403
    hist = (
        HistoricoLotacao.query.filter_by(funcionario_id=id)
        .order_by(HistoricoLotacao.data_mudanca.desc())
        .all()
    )
    html = ""
    if not hist:
        html = '<tr><td colspan="4" class="text-center p-4 text-gray-500">Nenhuma movimentação registrada.</td></tr>'
    for h in hist:
        nome_usuario = h.quem_mudou.username if h.quem_mudou else "Sistema"
        html += f"""<tr class="border-b border-gray-100"><td class="p-3 text-xs text-gray-500">{h.data_mudanca.strftime('%d/%m/%Y %H:%M')}</td><td class="p-3 text-sm font-medium">{h.antiga_secretaria}<br><span class="text-xs text-gray-400">{h.antigo_local}</span></td><td class="p-3 text-sm">{h.antiga_funcao}</td><td class="p-3 text-xs text-blue-600 font-bold">{nome_usuario}</td></tr>"""
    return html


@app.route("/validar_cadastros")
@login_required
def validar_cadastros():
    if current_user.role != "admin" and not getattr(current_user, "is_admin", False):
        flash("Acesso não autorizado.", "error")
        return redirect(url_for("sistema"))

    secretaria_id = request.args.get("secretaria_id")
    busca = request.args.get("busca")
    page = request.args.get("page", 1, type=int)

    query = Funcionario.query
    if secretaria_id:
        query = query.filter_by(secretaria_id=secretaria_id)
    if busca:
        term = f"%{busca.upper()}%"
        query = query.filter(
            (Funcionario.nome.like(term)) | (Funcionario.cpf.like(term))
        )

    pagination = query.order_by(
        Funcionario.validado.asc(), Funcionario.nome.asc()
    ).paginate(page=page, per_page=20, error_out=False)
    funcionarios = pagination.items
    secretarias = Secretaria.query.order_by(Secretaria.nome).all()
    return render_template(
        "validar_cadastros.html",
        funcionarios=funcionarios,
        secretarias=secretarias,
        pagination=pagination,
    )


@app.route("/aprovar_cadastro/<int:id>")
@login_required
def aprovar_cadastro(id):
    if current_user.role != "admin" and not getattr(current_user, "is_admin", False):
        flash("Acesso não autorizado.", "error")
        return redirect(url_for("sistema"))
    func = db.session.get(Funcionario, id)
    if func:
        func.validado = True
        db.session.commit()
        flash(f"Cadastro de {func.nome} validado com sucesso!", "success")
    return redirect(url_for("validar_cadastros"))


@app.route("/revogar_validacao/<int:id>")
@login_required
def revogar_validacao(id):
    if current_user.role != "admin" and not getattr(current_user, "is_admin", False):
        flash("Acesso não autorizado.", "error")
        return redirect(url_for("sistema"))
    func = db.session.get(Funcionario, id)
    if func:
        func.validado = False
        db.session.commit()
        flash(f"Validação de {func.nome} revogada com sucesso!", "success")
    return redirect(url_for("validar_cadastros"))


@app.route("/exportar_pendentes")
@login_required
def exportar_pendentes():
    if current_user.role != "admin" and not getattr(current_user, "is_admin", False):
        flash("Acesso não autorizado.", "error")
        return redirect(url_for("sistema"))

    secretaria_id = request.args.get("secretaria_id")
    busca = request.args.get("busca")

    query = Funcionario.query.filter_by(validado=False)

    if secretaria_id:
        query = query.filter_by(secretaria_id=secretaria_id)
    if busca:
        term = f"%{busca.upper()}%"
        query = query.filter(
            (Funcionario.nome.like(term)) | (Funcionario.cpf.like(term))
        )

    funcionarios = query.order_by(Funcionario.nome.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(["Nome", "CPF", "Secretaria", "Função", "Vínculo", "Data Criação"])
    for f in funcionarios:
        writer.writerow(
            [
                f.nome,
                f.cpf,
                f.secretaria.nome,
                f.funcao.nome if f.funcao else "",
                f.tipo_vinculo,
                f.data_criacao.strftime("%d/%m/%Y"),
            ]
        )
    output.seek(0)
    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=pendentes_validacao.csv"},
    )


@app.route("/recisoes")
@login_required
def pagina_recisoes():
    # Servidores ativos para o select/busca
    ativos = Funcionario.query.order_by(Funcionario.nome).all()
    # Histórico de quem já saiu
    historico = RescisaoHistorico.query.order_by(
        RescisaoHistorico.data_geracao.desc()
    ).all()
    return render_template("recisao_painel.html", ativos=ativos, historico=historico)


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    if request.method == "POST":
        # CRIAR SECRETARIA
        if "create_secretaria" in request.form:
            nome_sec = request.form.get("nome_secretaria").upper()
            if not Secretaria.query.filter_by(nome=nome_sec).first():
                db.session.add(Secretaria(nome=nome_sec))
                db.session.commit()
                registrar_log("CRIOU SECRETARIA", nome_sec)
                flash("Secretaria criada!", "success")

        # CRIAR FUNCAO
        if "create_funcao" in request.form:
            nome_funcao = request.form.get("nome_funcao").upper()
            if not Funcao.query.filter_by(nome=nome_funcao).first():
                db.session.add(Funcao(nome=nome_funcao))
                db.session.commit()
                flash("Função criada!", "success")

        if "create_local" in request.form:
            nome = request.form.get("nome_local")
            lat = request.form.get("latitude")
            lng = request.form.get("longitude")
            raio = request.form.get("raio_permitido")

            if nome:
                # Converte strings para float/int tratando campos vazios
                latitude = float(lat) if lat and lat.strip() else None
                longitude = float(lng) if lng and lng.strip() else None
                raio_permitido = int(raio) if raio and raio.strip() else 50

                novo_local = LocalTrabalho(
                    nome=nome,
                    latitude=latitude,
                    longitude=longitude,
                    raio_permitido=raio_permitido,
                )
                db.session.add(novo_local)
                db.session.commit()
                flash(f'Local "{nome}" cadastrado com sucesso!', "success")
            return redirect(url_for("admin_dashboard", tab="config"))

        # CRIAR PADRINHO
        if "create_padrinho" in request.form:
            nome_padrinho = request.form.get("nome_padrinho").upper()
            if not Padrinho.query.filter_by(nome=nome_padrinho).first():
                db.session.add(Padrinho(nome=nome_padrinho))
                db.session.commit()
                flash("Padrinho/Indicador criado!", "success")

        # CRIAR USUÁRIO
        elif "create_user" in request.form:
            username = request.form.get("username")
            sec_id_form = request.form.get("secretaria_id")
            role_form = request.form.get("role")

            if not sec_id_form:
                flash("Erro: Selecione uma Secretaria para o usuário!", "error")
            elif not User.query.filter_by(username=username).first():
                is_admin_bool = role_form == "admin"
                u = User(
                    username=username,
                    secretaria_id=int(sec_id_form),
                    role=role_form,
                    is_admin=is_admin_bool,
                )
                u.set_password(request.form.get("password"))
                db.session.add(u)
                db.session.commit()
                registrar_log("CRIOU USUÁRIO", f"{username} (Sec ID: {sec_id_form})")
                flash(f"Usuário {username} criado com sucesso!", "success")
            else:
                flash("Usuário já existe!", "error")

    # --- LÓGICA DE FILTRAGEM (CORRIGIDA) ---
    filtro_secretaria = request.args.get("secretaria_id")
    filtro_vinculo = request.args.get("tipo_vinculo")
    filtro_indicacao = request.args.get(
        "padrinho_id"
    )  # Mantido como string para o filtro
    filtro_funcao = request.args.get("funcao_id")
    filtro_local = request.args.get("local_trabalho_id")
    busca_termo = request.args.get("busca_termo")

    query = Funcionario.query

    if filtro_secretaria:
        query = query.filter_by(secretaria_id=filtro_secretaria)
    if filtro_vinculo:
        query = query.filter_by(tipo_vinculo=filtro_vinculo)
    if filtro_indicacao:
        query = query.filter_by(padrinho_id=filtro_indicacao)
    if filtro_funcao:
        query = query.filter_by(funcao_id=filtro_funcao)
    if filtro_local:
        query = query.filter_by(local_trabalho_id=filtro_local)

    if busca_termo:
        termo = f"%{busca_termo.upper()}%"
        query = query.filter(
            (Funcionario.nome.like(termo)) | (Funcionario.cpf.like(termo))
        )

    funcionarios_filtrados = query.order_by(Funcionario.nome).all()
    total_filtrado = len(funcionarios_filtrados)

    # Carregamento de dados para o Dashboard
    lista_padrinhos = Padrinho.query.order_by(Padrinho.nome).all()

    stats_sec_query = (
        db.session.query(Secretaria.nome, func.count(Funcionario.id))
        .join(Funcionario)
        .group_by(Secretaria.nome)
        .all()
    )
    stats_secretaria = {s[0]: s[1] for s in stats_sec_query}

    stats_vinculo_query = (
        db.session.query(Funcionario.tipo_vinculo, func.count(Funcionario.id))
        .group_by(Funcionario.tipo_vinculo)
        .all()
    )
    stats_vinculo = {
        (v[0] if v[0] else "Não Informado"): v[1] for v in stats_vinculo_query
    }

    count_validados = Funcionario.query.filter_by(validado=True).count()
    count_pendentes = Funcionario.query.filter_by(validado=False).count()
    stats_validacao = {"Aptos": count_validados, "Pendentes": count_pendentes}

    locais_stats_query = db.session.query(
        LocalTrabalho.nome, func.count(Funcionario.id)
    ).join(Funcionario, Funcionario.local_trabalho_id == LocalTrabalho.id)
    if filtro_secretaria:
        locais_stats_query = locais_stats_query.filter(
            Funcionario.secretaria_id == filtro_secretaria
        )
    locais_stats = (
        locais_stats_query.group_by(LocalTrabalho.nome)
        .order_by(func.count(Funcionario.id).desc())
        .all()
    )

    page_auditoria = request.args.get('page_auditoria', 1, type=int)
    per_page_auditoria = request.args.get('per_page_auditoria', 100, type=int)
    
    logs_pagination = LogAuditoria.query.order_by(LogAuditoria.data_hora.desc()).paginate(
        page=page_auditoria, per_page=per_page_auditoria, error_out=False
    )
    logs = logs_pagination.items
    secretarias = Secretaria.query.all()
    users = User.query.order_by(User.username).all()
    funcoes = Funcao.query.order_by(Funcao.nome).all()
    locais_trabalho = LocalTrabalho.query.order_by(LocalTrabalho.nome).all()

    return render_template(
        "admin.html",
        secretarias=secretarias,
        funcoes=funcoes,
        locais_trabalho=locais_trabalho,
        padrinhos=lista_padrinhos,
        users=users,
        funcionarios=funcionarios_filtrados,
        total_geral=total_filtrado,
        stats_secretaria=stats_secretaria,
        stats_vinculo=stats_vinculo,
        stats_validacao=stats_validacao,
        locais_stats=locais_stats,
        logs=logs,
        filtros={
            "sec": filtro_secretaria,
            "vinculo": filtro_vinculo,
            "indicacao": filtro_indicacao,
            "busca": busca_termo,
            "funcao": filtro_funcao,
            "local": filtro_local,
        },
        role=current_user.role,
        is_admin=current_user.is_admin,
    )


@app.route("/processar_recisao", methods=["POST"])
@login_required
def processar_recisao():
    id_func = request.form.get("id_funcionario")
    data_inicio_str = request.form.get("data_inicio")
    data_saida_str = request.form.get("data_saida")

    dt_ini = parse_date(data_inicio_str)
    dt_sai = parse_date(data_saida_str)

    funcionario = db.session.get(Funcionario, id_func)
    if not funcionario:
        flash("Servidor não encontrado", "error")
        return redirect(url_for("pagina_recisoes"))

    if not dt_ini:
        dt_ini = funcionario.dt_inicio
    if not dt_sai:
        dt_sai = date.today()

    try:
        # Salva no histórico carregando os dados completos do funcionário antes de excluí-lo!
        nova_rescisao = RescisaoHistorico(
            nome=funcionario.nome,
            cpf=funcionario.cpf,
            rg=funcionario.rg,
            endereco=funcionario.endereco,
            funcao=funcionario.funcao.nome if funcionario.funcao else "N/A",
            num_contrato=funcionario.num_vinculo, # Pega o vínculo atual como número do contrato
            data_inicio=dt_ini,
            data_saida=dt_sai,
        )
        db.session.add(nova_rescisao)

        # Prepara dados para o template imediato
        dados_doc = {
            "nome": funcionario.nome,
            "funcao": funcionario.funcao.nome if funcionario.funcao else "N/A",
            "data_inicio": dt_ini,
            "data_saida": dt_sai,
            "cpf": funcionario.cpf,
            "rg": funcionario.rg,
            "endereco": funcionario.endereco,
            "num_contrato": funcionario.num_vinculo
        }

        HistoricoLotacao.query.filter_by(funcionario_id=funcionario.id).delete()
        RegistroPonto.query.filter_by(funcionario_id=funcionario.id).delete()

        nome_servidor = funcionario.nome
        db.session.delete(funcionario)
        db.session.commit()
        
        registrar_log("GEROU RESCISAO", nome_servidor)

        fuso_br = pytz.timezone('America/Sao_Paulo')
        agora_br = datetime.now(fuso_br).replace(tzinfo=None)

        return render_template(
            "recisao_documento.html", f=dados_doc, data_atual=agora_br
        )

    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao processar baixa: {str(e)}", "error")
        return redirect(url_for("pagina_recisoes"))


@app.route("/admin/editar_local", methods=["POST"])
@login_required
def editar_local():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    id_local = request.form.get("id_local")
    local = db.session.get(LocalTrabalho, id_local)

    if local:
        local.nome = request.form.get("nome_local")
        lat = request.form.get("latitude")
        lng = request.form.get("longitude")
        raio = request.form.get("raio_permitido")

        local.latitude = float(lat) if lat and lat.strip() else None
        local.longitude = float(lng) if lng and lng.strip() else None
        local.raio_permitido = int(raio) if raio and raio.strip() else 50

        db.session.commit()
        registrar_log("EDITOU LOCAL", local.nome)
        flash("Configurações do local atualizadas!", "success")

    return redirect(url_for("admin_dashboard", tab="config"))


@app.route("/admin/reconhecimento_facial")
@login_required
def reconhecimento_facial():
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    # Busca todos os funcionários para a galeria
    funcionarios = Funcionario.query.order_by(Funcionario.nome).all()
    return render_template(
        "reconhecimento_facial.html", lista_funcionarios=funcionarios
    )


@app.route("/admin/cargos_total")
@login_required
def cargos_total():
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    # Pega todos os funcionários e suas funções
    funcionarios = Funcionario.query.all()

    stats_cargos = {}
    for f in funcionarios:
        nome_cargo = f.funcao.nome if f.funcao else "SEM CARGO"
        if nome_cargo not in stats_cargos:
            stats_cargos[nome_cargo] = {"total": 0, "servidores": []}

        stats_cargos[nome_cargo]["total"] += 1
        stats_cargos[nome_cargo]["servidores"].append(
            {
                "nome": f.nome,
                "cpf": f.cpf,
                "local": f.local_trabalho.nome if f.local_trabalho else "NÃO DEFINIDO",
                "vinculo": f.tipo_vinculo,
            }
        )

    # Ordena os cargos por nome
    stats_cargos = dict(sorted(stats_cargos.items()))

    return render_template("cargos_total.html", stats_cargos=stats_cargos)


@app.route("/excluir_ficha/<int:id>")
@login_required
def excluir_ficha(id):
    if not current_user.is_admin:
        flash("Apenas Admin pode excluir.", "error")
        return redirect(url_for("sistema"))
    ficha = db.session.get(Funcionario, id)
    if ficha:
        nome = ficha.nome
        HistoricoLotacao.query.filter_by(funcionario_id=id).delete()
        db.session.delete(ficha)
        db.session.commit()
        registrar_log("EXCLUIU FICHA", nome)
        flash("Ficha excluída.", "success")
    return redirect(url_for("sistema"))


@app.route("/admin/update_user", methods=["POST"])
@login_required
def update_user():
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    user_id = request.form.get("user_id")
    u = db.session.get(User, user_id)

    if u:
        # Username
        new_username = request.form.get("username")
        if new_username and new_username != u.username:
            if User.query.filter_by(username=new_username).first():
                flash("Nome de usuário já existe!", "error")
                return redirect(url_for("admin_dashboard"))
            u.username = new_username

        # Senha
        new_password = request.form.get("password")
        if new_password:
            u.set_password(new_password)

        # Secretaria e Role
        sec_id = request.form.get("secretaria_id")
        role = request.form.get("role")

        if sec_id:
            u.secretaria_id = int(sec_id)
        if role:
            u.role = role
            u.is_admin = role == "admin"

        db.session.commit()
        registrar_log("EDITOU USUÁRIO", u.username)
        flash("Usuário atualizado com sucesso!", "success")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for("sistema"))
    u = db.session.get(User, user_id)
    if u and not u.is_admin:
        db.session.delete(u)
        db.session.commit()
        flash("Usuário excluído.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_secretaria/<int:sec_id>")
@login_required
def delete_secretaria(sec_id):
    if not current_user.is_admin:
        return redirect(url_for("sistema"))
    if (
        User.query.filter_by(secretaria_id=sec_id).first()
        or Funcionario.query.filter_by(secretaria_id=sec_id).first()
    ):
        flash("Erro: Existem vínculos.", "error")
    else:
        s = db.session.get(Secretaria, sec_id)
        if s:
            db.session.delete(s)
            db.session.commit()
            flash("Secretaria excluída.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/editar_funcao", methods=["POST"])
@login_required
def editar_funcao():
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    id_funcao = request.form.get("id_funcao")
    novo_nome = request.form.get("nome_funcao", "").strip().upper()

    if not id_funcao or not novo_nome:
        flash("Erro: Nome da função é obrigatório.", "error")
        return redirect(url_for("admin_dashboard") + "?tab=config")

    funcao = db.session.get(Funcao, id_funcao)
    if not funcao:
        flash("Erro: Função não encontrada.", "error")
        return redirect(url_for("admin_dashboard") + "?tab=config")

    funcoes_protegidas = [
        "PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)",
        "PROFISSIONAL DE APOIO / CUIDADOR",
        "PROFISSIONAL DE APOIO (CUIDADOR)",
    ]

    if funcao.nome in funcoes_protegidas or novo_nome in funcoes_protegidas:
        flash(
            "Erro: A função 'PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)' é protegida do sistema e não pode ser alterada.",
            "error",
        )
        return redirect(url_for("admin_dashboard") + "?tab=config")

    existente = Funcao.query.filter(
        Funcao.nome == novo_nome, Funcao.id != id_funcao
    ).first()
    if existente:
        flash("Erro: Já existe outra função com esse nome.", "error")
        return redirect(url_for("admin_dashboard") + "?tab=config")

    nome_antigo = funcao.nome
    funcao.nome = novo_nome
    db.session.commit()
    registrar_log("EDITOU FUNCAO", f"{nome_antigo} -> {novo_nome}")
    flash(f"Função '{nome_antigo}' renomeada para '{novo_nome}' com sucesso!", "success")

    return redirect(url_for("admin_dashboard") + "?tab=config")


@app.route("/admin/delete_funcao/<int:id>")
@login_required
def delete_funcao(id):
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    f = db.session.get(Funcao, id)
    funcoes_protegidas = [
        "PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)",
        "PROFISSIONAL DE APOIO / CUIDADOR",
        "PROFISSIONAL DE APOIO (CUIDADOR)",
    ]
    if f and f.nome in funcoes_protegidas:
        flash("Erro: Esta função é protegida pelo sistema e não pode ser excluída.", "error")
        return redirect(url_for("admin_dashboard") + "?tab=config")

    if Funcionario.query.filter_by(funcao_id=id).first():
        flash("Erro: Existem funcionários com esta função.", "error")
    else:
        if f:
            db.session.delete(f)
            db.session.commit()
            flash("Função excluída.", "success")
    return redirect(url_for("admin_dashboard") + "?tab=config")


@app.route("/admin/delete_local/<int:id>")
@login_required
def delete_local(id):
    if not current_user.is_admin:
        return redirect(url_for("sistema"))
    if Funcionario.query.filter_by(local_trabalho_id=id).first():
        flash("Erro: Existem funcionários neste local.", "error")
    else:
        l = db.session.get(LocalTrabalho, id)
        if l:
            db.session.delete(l)
            db.session.commit()
            flash("Local de trabalho excluído.", "success")
    return redirect(url_for("admin_dashboard") + "?tab=config")


@app.route("/admin/delete_padrinho/<int:id>")
@login_required
def delete_padrinho(id):
    if not current_user.is_admin:
        return redirect(url_for("sistema"))
    if Funcionario.query.filter_by(padrinho_id=id).first():
        flash("Erro: Existem funcionários indicados por este padrinho.", "error")
    else:
        p = db.session.get(Padrinho, id)
        if p:
            db.session.delete(p)
            db.session.commit()
            flash("Padrinho/Indicador excluído.", "success")
    return redirect(url_for("admin_dashboard") + "?tab=config")


@app.route("/exportar_excel")
@login_required
def exportar_excel():
    # 1. Verificação de permissão
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    # 2. Captura dos filtros da URL para manter a precisão do relatório
    filtro_secretaria = request.args.get("secretaria_id")
    filtro_vinculo = request.args.get("tipo_vinculo")
    filtro_indicacao = request.args.get("padrinho_id")
    filtro_funcao = request.args.get("funcao_id")
    filtro_local = request.args.get("local_trabalho_id")

    # 3. Construção da Query filtrada
    query = Funcionario.query
    if filtro_secretaria:
        query = query.filter_by(secretaria_id=filtro_secretaria)
    if filtro_vinculo:
        query = query.filter_by(tipo_vinculo=filtro_vinculo)
    if filtro_indicacao:
        query = query.filter_by(padrinho_id=filtro_indicacao)
    if filtro_funcao:
        query = query.filter_by(funcao_id=filtro_funcao)
    if filtro_local:
        query = query.filter_by(local_trabalho_id=filtro_local)

    funcionarios = query.order_by(Funcionario.nome).all()

    # 4. Preparação do CSV
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")

    # Cabeçalho organizado para o Gestoor 360º com TODOS os novos campos
    header = [
        "Nº VÍNCULO",
        "NOME",
        "CPF",
        "RG",
        "ÓRGÃO EMISSOR",
        "DATA NASCIMENTO",
        "GÊNERO",
        "NOME DA MÃE",
        "NOME DO PAI",
        "EMAIL",
        "TELEFONE",
        "ESTADO CIVIL",
        "NACIONALIDADE",
        "ESCOLARIDADE",
        "ESPECIALIDADE",
        "PIS",
        "TÍTULO ELEITOR",
        "CTPS",
        "CNH",
        "DEPENDENTES",
        "PCD",
        "DEFICIÊNCIA",
        "TIPO SANGUÍNEO",
        "CONTATO EMERGÊNCIA",
        "TEL EMERGÊNCIA",
        "CEP",
        "ENDEREÇO",
        "BAIRRO",
        "CIDADE",
        "UF",
        "VÍNCULO",
        "LOCAL",
        "CLASSE",
        "Nº CONTRA CHEQUE",
        "FUNÇÃO",
        "LOTAÇÃO",
        "JORNADA",
        "REMUNERAÇÃO",
        "DADOS BANCÁRIOS",
        "DATA INÍCIO",
        "DATA TÉRMINO",
    ]
    writer.writerow(header)

    # 5. Preenchimento dos dados corrigindo os nomes das colunas do banco
    for f in funcionarios:
        # Formatação de dados bancários em uma única célula
        banco_info = f"Bco: {f.banco or ''}, Ag: {f.agencia or ''}, Cta: {f.conta or ''} ({f.tipo_conta or ''})"
        
        # Tratamento do campo PCD para o Excel
        pcd_info = "SIM" if f.is_pcd else "NÃO"

        writer.writerow(
            [
                f.num_vinculo,  # num_vinculo corrigido
                f.nome,
                f.cpf,
                f.rg,
                f.orgao_emissor_rg,
                (f.data_nasc.strftime("%d/%m/%Y") if f.data_nasc else ""),  # data_nasc corrigido
                f.genero,
                f.mae,  # mae corrigido
                f.pai,
                f.email,
                f.telefone,
                f.estado_civil,
                f.nacionalidade,
                f.escolaridade,
                (f.especialidade or ""),
                f.pis,  # pis corrigido
                f.titulo_eleitor,
                f.ctps,
                f.cnh,
                f.qtd_dependentes,
                pcd_info,
                f.tipo_deficiencia,
                f.tipo_sanguineo,
                f.contato_emergencia_nome,
                f.contato_emergencia_tel,
                f.cep,
                f.endereco,
                f.bairro,
                f.cidade,
                f.uf,
                f.tipo_vinculo,
                f.local_trabalho.nome if f.local_trabalho else "",
                f.classe,
                f.contracheque,
                f.funcao.nome if f.funcao else "",
                f.lotacao,
                f.jornada_trabalho,
                f.remuneracao,
                banco_info,
                (f.dt_inicio.strftime("%d/%m/%Y") if f.dt_inicio else ""),  # dt_inicio corrigido
                (f.dt_termino.strftime("%d/%m/%Y") if f.dt_termino else ""),  # dt_termino corrigido
            ]
        )

    # 6. Finalização e Log
    output.seek(0)
    registrar_log(
        "EXPORTOU DADOS", f"Relatório completo ({len(funcionarios)} registros)"
    )

    # Retorno com utf-8-sig para compatibilidade com Excel no Windows
    return Response(
        output.getvalue().encode("utf-8-sig"),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment;filename=exportacao_servidores_completa.csv"
        },
    )


def gerar_proximo_vinculo():
    """Gera o próximo número de vínculo no formato NUMERO/ANO."""
    ano_atual = datetime.now().year
    # Busca todos os vínculos do ano atual para processar em memória
    vinculos_ano = (
        db.session.query(Funcionario.num_vinculo)
        .filter(Funcionario.num_vinculo.like(f"%/{ano_atual}"))
        .all()
    )
    max_num = 0
    for v_tuple in vinculos_ano:
        v_str = v_tuple[0]
        if v_str and "/" in v_str:
            try:
                num_parte = int(v_str.split("/")[0])
                if num_parte > max_num:
                    max_num = num_parte
            except (ValueError, IndexError):
                continue  # Ignora formatos inválidos
    proximo_numero = max_num + 1
    return f"{proximo_numero}/{ano_atual}"


@app.route("/sistema", methods=["GET", "POST"])
@login_required
def sistema():
    # Carrega todas as opções para os formulários
    secretarias_opcoes = (
        Secretaria.query.order_by(Secretaria.nome).all()
        if current_user.is_admin
        else []
    )
    funcoes_opcoes = Funcao.query.order_by(Funcao.nome).all()
    locais_opcoes = LocalTrabalho.query.order_by(LocalTrabalho.nome).all()
    padrinhos_opcoes = Padrinho.query.order_by(Padrinho.nome).all()

    nome_secretaria_atual = (
        current_user.secretaria.nome if current_user.secretaria else "Sem Secretaria"
    )
    if current_user.is_admin:
        nome_secretaria_atual = "MODO ADMINISTRADOR"

    if request.method == "POST":
        is_indicacao = True if request.form.get("foi_indicacao") == "sim" else False
        padrinho_id = (
            request.form.get("padrinho_id")
            if is_indicacao and request.form.get("padrinho_id")
            else None
        )

        # LÓGICA DE SECRETARIA
        if current_user.is_admin:
            sec_id = request.form.get("secretaria_id")
            if not sec_id:
                flash("Selecione a Secretaria!", "error")
                return redirect(url_for("sistema"))
            sec_obj = db.session.get(Secretaria, int(sec_id))
            lotacao_texto = sec_obj.nome
        else:
            sec_id = current_user.secretaria_id
            lotacao_texto = (
                current_user.secretaria.nome
                if current_user.secretaria
                else "ADMINISTRAÇÃO"
            )

        dados_form = {
            "nome": request.form.get("nome").upper(),
            "num_vinculo": request.form.get("num_vinculo"),
            "cpf": request.form.get("cpf"),
            "rg": request.form.get("rg"),
            "data_expedicao_rg": parse_date(request.form.get("data_expedicao_rg")),
            "data_nasc": parse_date(request.form.get("data_nasc")),
            "pis": request.form.get("pis"),
            "titulo_eleitor": request.form.get("titulo_eleitor"),
            "zona_eleitoral": request.form.get("zona_eleitoral"),
            "secao_eleitoral": request.form.get("secao_eleitoral"),
            "mae": request.form.get("mae").upper(),
            "nacionalidade": request.form.get("nacionalidade"),
            "estado_civil": request.form.get("estado_civil"),
            "telefone": request.form.get("telefone"),
            "email": request.form.get("email"),
            "endereco": request.form.get("endereco").upper(),
            "funcao_id": request.form.get("funcao_id") or None,
            "local_trabalho_id": request.form.get("local_trabalho_id") or None,
            "tipo_vinculo": request.form.get("tipo_vinculo"),
            "classe": request.form.get("classe"),
            "contracheque": request.form.get("contracheque"),
            "remuneracao": request.form.get("remuneracao"),
            "jornada_trabalho": request.form.get("jornada_trabalho"),
            "dt_inicio": parse_date(request.form.get("dt_inicio")),
            "dt_termino": parse_date(request.form.get("dt_termino")),
            "banco": request.form.get("banco"),
            "agencia": request.form.get("agencia"),
            "conta": request.form.get("conta"),
            "tipo_conta": request.form.get("tipo_conta"),
            "foi_indicacao": is_indicacao,
            "padrinho_id": padrinho_id,
            "secretaria_id": int(sec_id),  # Força inteiro
            "lotacao": lotacao_texto,
            "crianca_assistida": (
                request.form.get("crianca_assistida").strip().upper()
                if request.form.get("crianca_assistida")
                and request.form.get("crianca_assistida").strip()
                else None
            ),
            
            # --- NOVOS CAMPOS ADICIONADOS AQUI ---
            "pai": request.form.get("pai").upper() if request.form.get("pai") else None,
            "orgao_emissor_rg": request.form.get("orgao_emissor_rg").upper() if request.form.get("orgao_emissor_rg") else None,
            "genero": request.form.get("genero"),
            "escolaridade": request.form.get("escolaridade"),
            "especialidade": (
                request.form.get("especialidade").strip().upper()
                if request.form.get("especialidade") and request.form.get("especialidade").strip()
                else None
            ),
            "cep": request.form.get("cep"),
            "bairro": request.form.get("bairro").upper() if request.form.get("bairro") else None,
            "cidade": request.form.get("cidade").upper() if request.form.get("cidade") else "VALENÇA DO PIAUÍ",
            "uf": request.form.get("uf").upper() if request.form.get("uf") else "PI",
            "is_pcd": True if request.form.get("is_pcd") == "sim" else False,
            "tipo_deficiencia": request.form.get("tipo_deficiencia").upper() if request.form.get("tipo_deficiencia") else None,
            "qtd_dependentes": int(request.form.get("qtd_dependentes")) if request.form.get("qtd_dependentes") and request.form.get("qtd_dependentes").isdigit() else 0,
            "ctps": request.form.get("ctps"),
            "cnh": request.form.get("cnh"),
            "contato_emergencia_nome": request.form.get("contato_emergencia_nome").upper() if request.form.get("contato_emergencia_nome") else None,
            "contato_emergencia_tel": request.form.get("contato_emergencia_tel"),
            "tipo_sanguineo": request.form.get("tipo_sanguineo"),
        }

        if not dados_form.get("dt_inicio"):
            flash("Data de Início é obrigatória!", "error")
            return redirect(url_for("sistema"))

        if not dados_form.get("cpf") or not dados_form.get("cpf").strip():
            flash("O CPF é obrigatório!", "error")
            return redirect(url_for("sistema"))

        if not dados_form.get("titulo_eleitor") or not str(dados_form.get("titulo_eleitor")).strip():
            flash("O Título de Eleitor é obrigatório!", "error")
            return redirect(url_for("sistema"))

        if not dados_form.get("zona_eleitoral") or not str(dados_form.get("zona_eleitoral")).strip():
            flash("A Zona Eleitoral é obrigatória!", "error")
            return redirect(url_for("sistema"))

        if not dados_form.get("secao_eleitoral") or not str(dados_form.get("secao_eleitoral")).strip():
            flash("A Seção Eleitoral é obrigatória!", "error")
            return redirect(url_for("sistema"))

        if not dados_form.get("escolaridade") or not dados_form.get("escolaridade").strip():
            flash("O Grau de Escolaridade é obrigatório!", "error")
            return redirect(url_for("sistema"))

        func_id = request.form.get("id")

        # Se for um novo cadastro, o campo num_vinculo é gerado automaticamente
        # e sobrescreve qualquer valor que venha do formulário.
        if not func_id:
            dados_form["num_vinculo"] = gerar_proximo_vinculo()

        # Validação de CPF duplicado
        cpf_normalizado = normalizar_cpf(dados_form["cpf"])
        cpf_duplicado = False
        if cpf_normalizado and len(cpf_normalizado) == 11:  # CPF válido tem 11 dígitos
            # Busca funcionários com o mesmo CPF
            funcionarios_com_mesmo_cpf = Funcionario.query.filter_by(
                cpf=dados_form["cpf"]
            ).all()

            # Se for edição, remove o próprio funcionário da lista
            if func_id:
                funcionarios_com_mesmo_cpf = [
                    f for f in funcionarios_com_mesmo_cpf if f.id != int(func_id)
                ]

            # Se encontrou duplicados, mostra alerta
            if funcionarios_com_mesmo_cpf:
                cpf_duplicado = True
                nomes_duplicados = [f.nome for f in funcionarios_com_mesmo_cpf]
                flash(
                    f'⚠️ ATENÇÃO: Este CPF já está cadastrado para: {", ".join(nomes_duplicados)}. Verifique se não está duplicando o cadastro.',
                    "error",
                )
                # Continua o processo mas alerta o usuário

        if func_id:
            funcionario = db.session.get(Funcionario, func_id)
            if funcionario:
                mudou_local = str(funcionario.local_trabalho_id) != str(
                    dados_form["local_trabalho_id"]
                )
                mudou_sec = str(funcionario.secretaria_id) != str(sec_id)
                mudou_funcao = str(funcionario.funcao_id) != str(
                    dados_form["funcao_id"]
                )

                if mudou_local or mudou_sec or mudou_funcao:
                    nova_funcao_obj = db.session.get(Funcao, dados_form["funcao_id"])
                    novo_local_obj = db.session.get(
                        LocalTrabalho, dados_form["local_trabalho_id"]
                    )
                    historico = HistoricoLotacao(
                        funcionario_id=funcionario.id,
                        antiga_secretaria=funcionario.lotacao,
                        antigo_local=(
                            funcionario.local_trabalho.nome
                            if funcionario.local_trabalho
                            else "N/A"
                        ),
                        antiga_funcao=(
                            funcionario.funcao.nome if funcionario.funcao else "N/A"
                        ),
                        quem_mudou_id=current_user.id,
                    )
                    db.session.add(historico)
                    registrar_log(
                        "MOVIMENTOU",
                        f"{funcionario.nome} -> {novo_local_obj.nome if novo_local_obj else 'N/A'}",
                    )
                else:
                    registrar_log("EDITOU", funcionario.nome)

                for key, value in dados_form.items():
                    setattr(funcionario, key, value)

                db.session.commit()
                if not cpf_duplicado:
                    flash("Dados atualizados com sucesso!", "success")
        else:
            novo_func = Funcionario(**dados_form)
            novo_func.criado_por = current_user.id
            db.session.add(novo_func)
            db.session.commit()
            registrar_log("CRIOU FICHA", f"{novo_func.nome} ({lotacao_texto})")
            if not cpf_duplicado:
                flash("Ficha criada com sucesso!", "success")

        return redirect(url_for("sistema"))

    query = Funcionario.query
    if not current_user.is_admin:
        query = query.filter_by(secretaria_id=current_user.secretaria_id)
    lista_funcionarios = query.order_by(Funcionario.id.desc()).all()
    proximo_vinculo_form = gerar_proximo_vinculo()

    # Pega o ID da função de apoio para a lógica do modal no frontend
    funcao_apoio = Funcao.query.filter(
        Funcao.nome.in_(
            [
                "PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)",
                "PROFISSIONAL DE APOIO / CUIDADOR",
            ]
        )
    ).first()
    funcao_apoio_id = funcao_apoio.id if funcao_apoio else None

    # Mapeia contratos gerados por funcionario_id, CPF e Nome para identificação direta
    contratos_gerados_todos = ContratoGerado.query.all()
    mapa_contratos_gerados = {}
    for cg in contratos_gerados_todos:
        if cg.funcionario_id:
            mapa_contratos_gerados[f"id_{cg.funcionario_id}"] = cg.num_contrato
        if cg.contratado_cpf and cg.contratado_cpf.strip():
            mapa_contratos_gerados[f"cpf_{cg.contratado_cpf.strip()}"] = cg.num_contrato
        if cg.contratado_nome and cg.contratado_nome.strip():
            mapa_contratos_gerados[f"nome_{cg.contratado_nome.strip().upper()}"] = cg.num_contrato

    return render_template(
        "sistema.html",
        nome_usuario=current_user.username,
        nome_secretaria=nome_secretaria_atual,
        lista_funcionarios=lista_funcionarios,
        secretarias_opcoes=secretarias_opcoes,
        funcoes_opcoes=funcoes_opcoes,
        locais_opcoes=locais_opcoes,
        padrinhos_opcoes=padrinhos_opcoes,
        is_admin=current_user.is_admin,
        role=current_user.role,
        proximo_vinculo_form=proximo_vinculo_form,
        funcao_apoio_id=funcao_apoio_id,
        mapa_contratos_gerados=mapa_contratos_gerados,
    )


def create_admin():
    with app.app_context():
        db.create_all()
        user = User.query.filter_by(username="admin").first()
        if not user:
            # Verifica se a secretaria já existe para não duplicar
            sec_adm = Secretaria.query.filter_by(nome="PREFEITURA MUNICIPAL").first()
            if not sec_adm:
                sec_adm = Secretaria(nome="PREFEITURA MUNICIPAL")
                db.session.add(sec_adm)
                db.session.commit()

            # Pega a senha de uma variável de ambiente ou usa uma padrão apenas na primeira vez
            senha_inicial = os.getenv("ADMIN_INITIAL_PASSWORD", "Mudar123@")

            user = User(
                username="admin", is_admin=True, role="admin", secretaria_id=sec_adm.id
            )
            user.set_password(senha_inicial)
            db.session.add(user)
            db.session.commit()
            print(f"ADMINISTRADOR CRIADO COM SENHA INICIAL: {senha_inicial}")


def atualizar_schema():
    """Função robusta para adicionar colunas no SQLite ou PostgreSQL (Railway)"""
    with app.app_context():
        with db.engine.connect() as conn:
            # 1. Colunas para a tabela 'funcionario'
            colunas_funcionario = [
                ("padrinho_id", "INTEGER"),
                ("funcao_id", "INTEGER"),
                ("local_trabalho_id", "INTEGER"),
                ("validado", "BOOLEAN DEFAULT FALSE"),
                ("data_expedicao_rg", "DATE"),
                ("jornada_trabalho", "VARCHAR(50)"),
                ("crianca_assistida", "VARCHAR(150)"),
                ("foto_biometria", "TEXT"),
                ("foto_path", "VARCHAR(255)"),
                # --- NOVOS CAMPOS ADICIONADOS ---
                ("pai", "VARCHAR(150)"),
                ("orgao_emissor_rg", "VARCHAR(20)"),
                ("genero", "VARCHAR(20)"),
                ("escolaridade", "VARCHAR(100)"),
                ("especialidade", "VARCHAR(150)"),
                ("cep", "VARCHAR(10)"),
                ("bairro", "VARCHAR(100)"),
                ("cidade", "VARCHAR(100) DEFAULT 'Valença do Piauí'"),
                ("uf", "VARCHAR(2) DEFAULT 'PI'"),
                ("is_pcd", "BOOLEAN DEFAULT FALSE"),
                ("tipo_deficiencia", "VARCHAR(100)"),
                ("qtd_dependentes", "INTEGER DEFAULT 0"),
                ("ctps", "VARCHAR(50)"),
                ("cnh", "VARCHAR(20)"),
                ("contato_emergencia_nome", "VARCHAR(150)"),
                ("contato_emergencia_tel", "VARCHAR(20)"),
                ("tipo_sanguineo", "VARCHAR(5)"),
            ]

            # 2. Colunas para a tabela 'local_trabalho'
            colunas_local = [
                ("latitude", "FLOAT"),
                ("longitude", "FLOAT"),
                ("raio_permitido", "INTEGER DEFAULT 50"),
            ]

            # 3. Novas colunas para a tabela 'rescisao_historico' (Salvamento permanente)
            colunas_rescisao = [
                ("rg", "VARCHAR(20)"),
                ("endereco", "VARCHAR(200)"),
                ("num_contrato", "VARCHAR(50)")
            ]
            
            # 4. Novas colunas para a tabela 'log_auditoria' (Rastreamento Minucioso)
            colunas_log = [
                ("tabela_afetada", "VARCHAR(50)"),
                ("registro_id", "INTEGER"),
                ("dados_antigos", "TEXT"),
                ("dados_novos", "TEXT"),
                ("ip_origem", "VARCHAR(50)"),
                ("user_agent", "VARCHAR(255)"),
                ("rota_acessada", "VARCHAR(255)")
            ]

            # Processa tabela funcionario
            for col, tipo in colunas_funcionario:
                try:
                    conn.execute(text(f"ALTER TABLE funcionario ADD COLUMN {col} {tipo}"))
                    conn.commit()
                except Exception as e:
                    conn.rollback() 

            # Processa tabela local_trabalho
            for col, tipo in colunas_local:
                try:
                    conn.execute(text(f"ALTER TABLE local_trabalho ADD COLUMN {col} {tipo}"))
                    conn.commit()
                except Exception as e:
                    conn.rollback()

            # Processa tabela rescisao_historico (POSTGRESQL RAILWAY)
            for col, tipo in colunas_rescisao:
                try:
                    conn.execute(text(f"ALTER TABLE rescisao_historico ADD COLUMN {col} {tipo}"))
                    conn.commit()
                    print(f"SUCESSO: Coluna '{col}' adicionada em 'rescisao_historico'.")
                except Exception as e:
                    conn.rollback()
                    
            # 5. Novas colunas para a tabela 'contrato_gerado' (Rastreamento de Edição)
            colunas_contrato = [
                ("editado", "BOOLEAN DEFAULT FALSE"),
                ("motivo_edicao", "TEXT"),
                ("data_edicao", "TIMESTAMP"),
                ("quem_editou_id", "INTEGER")
            ]

            # Processa tabela log_auditoria
            for col, tipo in colunas_log:
                try:
                    conn.execute(text(f"ALTER TABLE log_auditoria ADD COLUMN {col} {tipo}"))
                    conn.commit()
                    print(f"SUCESSO: Coluna '{col}' adicionada em 'log_auditoria'.")
                except Exception as e:
                    conn.rollback()

            # Processa tabela contrato_gerado
            for col, tipo in colunas_contrato:
                try:
                    conn.execute(text(f"ALTER TABLE contrato_gerado ADD COLUMN {col} {tipo}"))
                    conn.commit()
                    print(f"SUCESSO: Coluna '{col}' adicionada em 'contrato_gerado'.")
                except Exception as e:
                    conn.rollback()

            # 6. Novas colunas para a tabela 'user' (Aceite do Termo de Responsabilidade)
            colunas_user = [
                ("termo_aceito", "BOOLEAN DEFAULT FALSE"),
                ("termo_aceito_em", "TIMESTAMP")
            ]
            for col, tipo in colunas_user:
                try:
                    conn.execute(text(f"ALTER TABLE \"user\" ADD COLUMN {col} {tipo}"))
                    conn.commit()
                    print(f"SUCESSO: Coluna '{col}' adicionada em 'user'.")
                except Exception as e:
                    conn.rollback()

            # 5. Migração automática do nome da Função de Apoio (no Railway PostgreSQL e SQLite local)
            try:
                conn.execute(
                    text(
                        "UPDATE funcao SET nome = 'PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)' "
                        "WHERE nome IN ('PROFISSIONAL DE APOIO / CUIDADOR', 'PROFISSIONAL DE APOIO (CUIDADOR)') "
                        "AND NOT EXISTS (SELECT 1 FROM funcao WHERE nome = 'PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)')"
                    )
                )
                conn.commit()
            except Exception as e:
                conn.rollback()

            try:
                row_nova = conn.execute(
                    text("SELECT id FROM funcao WHERE nome = 'PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)'")
                ).fetchone()
                if row_nova:
                    id_novo = row_nova[0]
                    rows_antigas = conn.execute(
                        text("SELECT id FROM funcao WHERE nome IN ('PROFISSIONAL DE APOIO / CUIDADOR', 'PROFISSIONAL DE APOIO (CUIDADOR)') AND id != :id_novo"),
                        {"id_novo": id_novo}
                    ).fetchall()
                    for r in rows_antigas:
                        id_antigo = r[0]
                        conn.execute(text("UPDATE funcionario SET funcao_id = :id_novo WHERE funcao_id = :id_antigo"), {"id_novo": id_novo, "id_antigo": id_antigo})
                        conn.execute(text("DELETE FROM funcao WHERE id = :id_antigo"), {"id_antigo": id_antigo})
                    conn.commit()
            except Exception as e:
                conn.rollback()

            # Garantir que a nova tabela contrato_gerado seja criada
            try:
                db.create_all()
            except Exception as e:
                pass


@app.route("/api/aceitar_termo", methods=["POST"])
@login_required
def aceitar_termo():
    try:
        current_user.termo_aceito = True
        current_user.termo_aceito_em = datetime.utcnow()
        db.session.commit()

        registrar_log("Aceitou Termo", f"Usuário {current_user.username} aceitou o Termo de Responsabilidade e Segurança (LGPD)")

        data_formatada = current_user.termo_aceito_em.strftime("%d/%m/%Y às %H:%M")
        return {
            "success": True,
            "username": current_user.username,
            "data_aceite": data_formatada
        }
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.context_processor
def utility_processor():
    def buscar_contrato_existente(func):
        if not func:
            return None
        try:
            if func.id:
                c = ContratoGerado.query.filter_by(funcionario_id=func.id).first()
                if c:
                    return c
            if func.cpf and str(func.cpf).strip():
                c = ContratoGerado.query.filter_by(contratado_cpf=str(func.cpf).strip()).first()
                if c:
                    return c
            if func.nome and str(func.nome).strip():
                c = ContratoGerado.query.filter(db.func.upper(ContratoGerado.contratado_nome) == str(func.nome).strip().upper()).first()
                if c:
                    return c
        except Exception:
            pass
        return None
    return dict(buscar_contrato_existente=buscar_contrato_existente)


@app.route("/api/proximo_numero_contrato")
@login_required
def api_proximo_numero_contrato():
    if not current_user.is_admin and getattr(current_user, "role", "") != "admin":
        return {"num_contrato": "01/2026"}, 403
    ano = request.args.get("ano", type=int) or datetime.now().year
    proximo = gerar_proximo_numero_contrato(ano)
    return {"num_contrato": proximo}


@app.route("/gerar_contrato", methods=["POST"])
@login_required
def processar_gerar_contrato():
    if not current_user.is_admin and getattr(current_user, "role", "") != "admin":
        return {"success": False, "message": "Acesso negado: Apenas administradores podem gerar contratos."}, 403
    try:
        funcionario_id = request.form.get("funcionario_id", type=int)
        contratado_cpf = request.form.get("contratado_cpf", "").strip()
        contratado_nome = request.form.get("contratado_nome", "").strip()
        
        # O servidor não pode ter contrato gerado mais de uma vez (verifica por ID, CPF e Nome)
        existente = None
        if funcionario_id:
            existente = ContratoGerado.query.filter_by(funcionario_id=funcionario_id).first()
        if not existente and contratado_cpf:
            existente = ContratoGerado.query.filter_by(contratado_cpf=contratado_cpf).first()
        if not existente and contratado_nome:
            existente = ContratoGerado.query.filter(db.func.upper(ContratoGerado.contratado_nome) == contratado_nome.upper()).first()

        if existente:
            return {
                "success": False,
                "message": f"Este servidor já possui um contrato gerado (Nº {existente.num_contrato}). Cada servidor só pode ter 1 contrato gerado. Utilize a opção de edição na página 'Contratos Gerados' para alterá-lo.",
                "existente_num": existente.num_contrato,
                "existente_id": existente.id
            }, 400

        num_contrato = request.form.get("num_contrato")
        dt_inicio_str = request.form.get("dt_inicio")
        dt_termino_str = request.form.get("dt_termino")
        dt_assinatura_str = request.form.get("dt_assinatura")
        
        contratado_nome = request.form.get("contratado_nome", "").strip()
        contratado_cpf = request.form.get("contratado_cpf", "").strip()
        contratado_rg = request.form.get("contratado_rg", "").strip()
        contratado_nacionalidade = request.form.get("contratado_nacionalidade", "brasileiro(a)").strip()
        contratado_naturalidade = request.form.get("contratado_naturalidade", "piauiense").strip()
        contratado_estado_civil = request.form.get("contratado_estado_civil", "solteiro(a)").strip()
        contratado_endereco = request.form.get("contratado_endereco", "").strip()
        
        funcao_nome = request.form.get("funcao_nome", "").strip()
        jornada_trabalho = request.form.get("jornada_trabalho", "").strip()
        remuneracao = request.form.get("remuneracao", "").strip()
        remuneracao_extenso = request.form.get("remuneracao_extenso", "").strip()
        
        representante_nome = request.form.get("representante_nome", "MARIA EDNA DE SOUSA QUARESMA").strip()
        representante_cargo = request.form.get("representante_cargo", "Secretária Municipal de Educação").strip()
        representante_rg_cpf = request.form.get("representante_rg_cpf", "676.079.263-72").strip()
        representante_endereco = request.form.get("representante_endereco", "Rua Coronel Anibal Martins, nº 455 - Novo Horizonte, Valença do Piauí - PI").strip()

        dt_inicio = parse_date(dt_inicio_str) if dt_inicio_str else date.today()
        dt_termino = parse_date(dt_termino_str) if dt_termino_str else None
        dt_assinatura = parse_date(dt_assinatura_str) if dt_assinatura_str else (dt_inicio or date.today())
        
        ano_exercicio = dt_inicio.year if dt_inicio else datetime.now().year
        
        if not num_contrato:
            num_contrato = gerar_proximo_numero_contrato(ano_exercicio)

        novo_contrato = ContratoGerado(
            num_contrato=num_contrato,
            ano_exercicio=ano_exercicio,
            funcionario_id=funcionario_id,
            contratado_nome=contratado_nome,
            contratado_cpf=contratado_cpf,
            contratado_rg=contratado_rg,
            contratado_nacionalidade=contratado_nacionalidade,
            contratado_naturalidade=contratado_naturalidade,
            contratado_estado_civil=contratado_estado_civil,
            contratado_endereco=contratado_endereco,
            funcao_nome=funcao_nome,
            remuneracao=remuneracao,
            remuneracao_extenso=remuneracao_extenso,
            jornada_trabalho=jornada_trabalho,
            dt_inicio=dt_inicio,
            dt_termino=dt_termino,
            dt_assinatura=dt_assinatura,
            representante_nome=representante_nome,
            representante_cargo=representante_cargo,
            representante_rg_cpf=representante_rg_cpf,
            representante_endereco=representante_endereco,
            quem_gerou_id=current_user.id,
            data_geracao=datetime.utcnow()
        )

        db.session.add(novo_contrato)
        db.session.commit()

        registrar_log("Gerou Contrato", f"Contrato Nº {num_contrato} - {contratado_nome}")

        return {
            "success": True,
            "contrato_id": novo_contrato.id,
            "view_url": url_for("visualizar_contrato_documento", id=novo_contrato.id)
        }
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route("/contrato/editar/<int:id>", methods=["POST"])
@login_required
def editar_contrato(id):
    if not current_user.is_admin and getattr(current_user, "role", "") != "admin":
        return {"success": False, "message": "Acesso negado: Apenas administradores podem editar contratos."}, 403

    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        return {"success": False, "message": "Contrato não encontrado."}, 404

    motivo = request.form.get("motivo_edicao", "").strip()
    if not motivo:
        return {"success": False, "message": "É obrigatório informar o motivo da edição do contrato."}, 400

    try:
        # Manter num_contrato e ano_exercicio originais intactos
        contrato.contratado_nome = request.form.get("contratado_nome", "").strip()
        contrato.contratado_cpf = request.form.get("contratado_cpf", "").strip()
        contrato.contratado_rg = request.form.get("contratado_rg", "").strip()
        contrato.contratado_nacionalidade = request.form.get("contratado_nacionalidade", "brasileiro(a)").strip()
        contrato.contratado_naturalidade = request.form.get("contratado_naturalidade", "piauiense").strip()
        contrato.contratado_estado_civil = request.form.get("contratado_estado_civil", "solteiro(a)").strip()
        contrato.contratado_endereco = request.form.get("contratado_endereco", "").strip()

        contrato.funcao_nome = request.form.get("funcao_nome", "").strip()
        contrato.jornada_trabalho = request.form.get("jornada_trabalho", "").strip()
        contrato.remuneracao = request.form.get("remuneracao", "").strip()
        contrato.remuneracao_extenso = request.form.get("remuneracao_extenso", "").strip()

        dt_inicio_str = request.form.get("dt_inicio")
        dt_termino_str = request.form.get("dt_termino")
        dt_assinatura_str = request.form.get("dt_assinatura")

        if dt_inicio_str: contrato.dt_inicio = parse_date(dt_inicio_str)
        if dt_termino_str: contrato.dt_termino = parse_date(dt_termino_str)
        if dt_assinatura_str: contrato.dt_assinatura = parse_date(dt_assinatura_str)

        contrato.representante_nome = request.form.get("representante_nome", "MARIA EDNA DE SOUSA QUARESMA").strip()
        contrato.representante_cargo = request.form.get("representante_cargo", "Secretária Municipal de Educação").strip()
        contrato.representante_rg_cpf = request.form.get("representante_rg_cpf", "676.079.263-72").strip()
        contrato.representante_endereco = request.form.get("representante_endereco", "Rua Coronel Anibal Martins, nº 455 - Novo Horizonte, Valença do Piauí - PI").strip()

        contrato.editado = True
        contrato.motivo_edicao = motivo
        contrato.data_edicao = datetime.utcnow()
        contrato.quem_editou_id = current_user.id

        db.session.commit()

        registrar_log("Editou Contrato", f"Contrato Nº {contrato.num_contrato} ({contrato.contratado_nome}) - Motivo: {motivo}")

        return {
            "success": True,
            "contrato_id": contrato.id,
            "view_url": url_for("visualizar_contrato_documento", id=contrato.id)
        }
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route("/contratos")
@login_required
def pagina_contratos():
    if not current_user.is_admin and getattr(current_user, "role", "") != "admin":
        flash("Acesso negado: Apenas administradores podem visualizar os contratos gerados.", "danger")
        return redirect(url_for("sistema"))
    historico = ContratoGerado.query.order_by(ContratoGerado.data_geracao.desc()).all()
    return render_template("contratos_painel.html", historico=historico)


def formatar_remuneracao_rs(valor_str):
    if not valor_str:
        return "R$0,00"
    v = str(valor_str).strip()
    if not v.startswith("R$"):
        return f"R${v}"
    return v


@app.route("/contrato/documento/<int:id>")
@login_required
def visualizar_contrato_documento(id):
    if not current_user.is_admin and getattr(current_user, "role", "") != "admin":
        flash("Acesso negado: Apenas administradores podem visualizar contratos.", "danger")
        return redirect(url_for("sistema"))
    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        return "Contrato não encontrado", 404

    contrato_dict = {
        "id": contrato.id,
        "num_contrato": contrato.num_contrato,
        "ano_exercicio": contrato.ano_exercicio,
        "contratado_nome": contrato.contratado_nome,
        "contratado_cpf": contrato.contratado_cpf or "",
        "contratado_rg": contrato.contratado_rg or "",
        "contratado_nacionalidade": contrato.contratado_nacionalidade or "brasileiro(a)",
        "contratado_naturalidade": contrato.contratado_naturalidade or "piauiense",
        "contratado_estado_civil": contrato.contratado_estado_civil or "solteiro(a)",
        "contratado_endereco": contrato.contratado_endereco or "",
        "funcao_nome": contrato.funcao_nome or "",
        "remuneracao": contrato.remuneracao or "",
        "remuneracao_formatada": formatar_remuneracao_rs(contrato.remuneracao),
        "remuneracao_extenso": contrato.remuneracao_extenso or "",
        "jornada_trabalho": contrato.jornada_trabalho or "",
        "dt_inicio_extenso": formatar_data_extenso(contrato.dt_inicio),
        "dt_termino_extenso": formatar_data_extenso(contrato.dt_termino),
        "dt_assinatura_extenso": formatar_data_extenso(contrato.dt_assinatura or contrato.dt_inicio),
        "dt_termino_formatada": contrato.dt_termino.strftime("%d/%m/%Y") if contrato.dt_termino else "",
        "dt_assinatura_formatada": contrato.dt_assinatura.strftime("%d/%m/%Y") if contrato.dt_assinatura else (contrato.dt_inicio.strftime("%d/%m/%Y") if contrato.dt_inicio else ""),
        "representante_nome": contrato.representante_nome,
        "representante_cargo": contrato.representante_cargo,
        "representante_rg_cpf": contrato.representante_rg_cpf,
        "representante_endereco": contrato.representante_endereco,
    }

    return render_template("contrato_documento.html", contrato=contrato_dict)


@app.route("/contrato/extrato/<int:id>")
@login_required
def visualizar_contrato_extrato(id):
    if not current_user.is_admin and getattr(current_user, "role", "") != "admin":
        flash("Acesso negado: Apenas administradores podem visualizar os extratos.", "danger")
        return redirect(url_for("sistema"))
    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        return "Contrato não encontrado", 404

    contrato_dict = {
        "id": contrato.id,
        "num_contrato": contrato.num_contrato,
        "ano_exercicio": contrato.ano_exercicio,
        "contratado_nome": contrato.contratado_nome,
        "funcao_nome": contrato.funcao_nome or "",
        "remuneracao": contrato.remuneracao or "",
        "remuneracao_formatada": formatar_remuneracao_rs(contrato.remuneracao),
        "remuneracao_extenso": contrato.remuneracao_extenso or "",
        "dt_termino_formatada": contrato.dt_termino.strftime("%d/%m/%Y") if contrato.dt_termino else "",
        "dt_assinatura_formatada": contrato.dt_assinatura.strftime("%d/%m/%Y") if contrato.dt_assinatura else (contrato.dt_inicio.strftime("%d/%m/%Y") if contrato.dt_inicio else ""),
    }

    return render_template("contrato_extrato.html", contrato=contrato_dict)


@app.route("/contrato/excluir/<int:id>", methods=["POST"])
@login_required
def excluir_contrato(id):
    if not current_user.is_admin:
        flash("Apenas administradores podem excluir registros de contratos.", "danger")
        return redirect(url_for("pagina_contratos"))

    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("pagina_contratos"))

    try:
        num = contrato.num_contrato
        nome = contrato.contratado_nome
        db.session.delete(contrato)
        db.session.commit()
        registrar_log("Excluiu Contrato", f"Contrato Nº {num} - {nome}")
        flash(f"Contrato Nº {num} excluído com sucesso.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao excluir contrato: {str(e)}", "danger")

    return redirect(url_for("pagina_contratos"))


@app.route("/imprimir_encaminhamento/<int:id>")
@login_required
def imprimir_encaminhamento(id):
    funcionario = db.session.get(Funcionario, id)
    if not funcionario:
        return "Funcionário não encontrado", 404

    hoje = datetime.now()
    meses = [
        "Janeiro",
        "Fevereiro",
        "Março",
        "Abril",
        "Maio",
        "Junho",
        "Julho",
        "Agosto",
        "Setembro",
        "Outubro",
        "Novembro",
        "Dezembro",
    ]
    data_extenso = f"{hoje.day} de {meses[hoje.month - 1]} de {hoje.year}"

    return render_template(
        "encaminhamento.html",
        funcionario=funcionario,
        data_extenso=data_extenso,
        ano=hoje.year,
    )


@app.route("/apoio_pedagogico")
@login_required
def apoio_pedagogico():
    if not current_user.is_admin:
        flash("Acesso não autorizado.", "error")
        return redirect(url_for("sistema"))

    cuidadores = (
        Funcionario.query.join(Funcao)
        .filter(
            Funcao.nome.in_(
                [
                    "PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)",
                    "PROFISSIONAL DE APOIO / CUIDADOR",
                ]
            ),
            Funcionario.crianca_assistida.isnot(None),
        )
        .order_by(Funcionario.crianca_assistida)
        .all()
    )
    return render_template("apoio_pedagogico.html", cuidadores=cuidadores)


@app.route("/fotos")
@login_required
def gerenciar_fotos():
    funcionarios = Funcionario.query.order_by(Funcionario.nome).all()
    return render_template("fotos.html", funcionarios=funcionarios)


@app.route("/admin/folha_pagamento", methods=["GET"])
@login_required
def folha_pagamento():
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    locais_trabalho = LocalTrabalho.query.order_by(LocalTrabalho.nome).all()

    local_id_filtro = request.args.get("local_id")
    funcionarios_folha = []
    local_selecionado = None

    if local_id_filtro:
        # Removido o filtro 'validado=True' para permitir a exibição de todos os servidores do local
        funcionarios_folha = (
            Funcionario.query.filter_by(local_trabalho_id=local_id_filtro)
            .order_by(Funcionario.nome)
            .all()
        )

        local_selecionado = db.session.get(LocalTrabalho, local_id_filtro)

    return render_template(
        "folha_pagamento.html",
        locais_trabalho=locais_trabalho,
        funcionarios_folha=funcionarios_folha,
        local_selecionado=local_selecionado,
    )


@app.route("/admin/ponto", methods=["GET"])
@login_required
def painel_ponto():
    """Painel interno para visualizar registros de ponto de todos os servidores."""
    # Permite admin, RH secretaria e supervisor (visualização).
    if not (
        getattr(current_user, "is_admin", False)
        or current_user.role in ["admin", "rh_secretaria", "rh_supervisor"]
    ):
        return redirect(url_for("sistema"))

    secretaria_id = request.args.get("secretaria_id")
    busca_nome = request.args.get("busca_nome")
    mes = request.args.get("mes")
    # Horários esperados (entrada 1 e retorno)
    inicio_20 = request.args.get("inicio_20", "07:00")
    inicio_40 = request.args.get("inicio_40", "07:00")
    entrada_2 = request.args.get("entrada_2", "13:30")
    tolerancia_min = request.args.get("tolerancia_min", "0")

    if not mes:
        mes = datetime.utcnow().strftime("%Y-%m")

    try:
        tolerancia_min = int(tolerancia_min)
    except:
        tolerancia_min = 0

    def parse_hhmm(hhmm):
        try:
            hh, mm = str(hhmm).split(":", 1)
            return int(hh), int(mm)
        except:
            return None, None

    hh20, mm20 = parse_hhmm(inicio_20)
    hh40, mm40 = parse_hhmm(inicio_40)
    hh2, mm2 = parse_hhmm(entrada_2)

    def parse_jornada_trabalho(jornada_str):
        if not jornada_str:
            return None
        try:
            num = int("".join([c for c in str(jornada_str) if c.isdigit()]))
            if num in (20, 30, 40):
                return num
        except:
            pass
        return None

    def calcular_atraso_min(entrada_dt, jornada_trabalho, entrada_idx):
        if not entrada_dt:
            return 0

        jornada = parse_jornada_trabalho(jornada_trabalho)
        exp_hh = None
        exp_mm = None

        # 0 = primeira entrada do dia (07:00)
        # 1 = retorno do intervalo (13:30)
        if entrada_idx == 0:
            if jornada == 20 and (hh20 is not None and mm20 is not None):
                exp_hh, exp_mm = hh20, mm20
            elif jornada == 40 and (hh40 is not None and mm40 is not None):
                exp_hh, exp_mm = hh40, mm40
            elif jornada in (None, 20, 40):
                # Caso jornada esteja vazia, tenta usar 40h (mais comum no seu exemplo).
                if hh40 is not None and mm40 is not None:
                    exp_hh, exp_mm = hh40, mm40
        elif entrada_idx == 1:
            if hh2 is not None and mm2 is not None:
                exp_hh, exp_mm = hh2, mm2
        else:
            return 0

        if exp_hh is None or exp_mm is None:
            return 0

        exp_dt = entrada_dt.replace(hour=exp_hh, minute=exp_mm, second=0, microsecond=0)

        atraso = int((entrada_dt - exp_dt).total_seconds() / 60)
        if atraso <= 0:
            return 0
        atraso_liquido = atraso - tolerancia_min if tolerancia_min else atraso
        return max(0, atraso_liquido)

    # Intervalo do mês (UTC/naive)
    start_month = datetime.strptime(mes, "%Y-%m")
    if start_month.month == 12:
        end_month = datetime(start_month.year + 1, 1, 1)
    else:
        end_month = datetime(start_month.year, start_month.month + 1, 1)

    query = RegistroPonto.query.join(Funcionario)
    if secretaria_id:
        query = query.filter(Funcionario.secretaria_id == secretaria_id)
    if busca_nome:
        termo = f"%{busca_nome.upper()}%"
        query = query.filter(Funcionario.nome.like(termo))

    secretarias = Secretaria.query.order_by(Secretaria.nome).all()

    query_mes = query.filter(
        RegistroPonto.data_hora >= start_month, RegistroPonto.data_hora < end_month
    )

    # Para a tabela (performance)
    registros = query_mes.order_by(RegistroPonto.data_hora.desc()).limit(1000).all()

    # Para o resumo (atraso por servidor)
    entradas_mes = (
        query_mes.filter(RegistroPonto.tipo == "entrada")
        .order_by(RegistroPonto.data_hora.desc())
        .all()
    )

    # Calcula atraso considerando:
    # - primeira entrada do dia (entrada_idx=0)
    # - retorno do intervalo (entrada_idx=1)
    # Soma em minutos e depois converte para horas no resumo.
    entradas_por_dia = {}
    for e in entradas_mes:
        if not getattr(e, "data_hora", None):
            continue
        dia = e.data_hora.date()
        k = (e.funcionario_id, dia)
        entradas_por_dia.setdefault(k, []).append(e)

    entry_id_to_atraso = {}
    resumo = {}
    atraso_total_geral_min = 0

    for (func_id, dia), entries in entradas_por_dia.items():
        entries_sorted = sorted(entries, key=lambda x: x.data_hora)

        # Só consideramos as duas primeiras entradas do dia.
        for idx, e in enumerate(entries_sorted[:2]):
            atraso = calcular_atraso_min(
                e.data_hora, e.funcionario.jornada_trabalho, idx
            )
            entry_id_to_atraso[e.id] = atraso
            atraso_total_geral_min += atraso

            if func_id not in resumo:
                resumo[func_id] = {
                    "funcionario_id": func_id,
                    "nome": e.funcionario.nome,
                    "total_minutos": 0,
                    "total_horas": 0.0,
                }
            resumo[func_id]["total_minutos"] += atraso

    # Atribui atraso por linha (apenas para entradas exibidas no limite da tabela)
    for r in registros:
        r.atraso_minutos = 0
        if getattr(r, "tipo", None) == "entrada":
            r.atraso_minutos = entry_id_to_atraso.get(r.id, 0)

    for key, v in resumo.items():
        v["total_horas"] = round(v["total_minutos"] / 60.0, 2)

    resumo_servidores = list(resumo.values())
    resumo_servidores.sort(key=lambda x: x["total_minutos"], reverse=True)

    return render_template(
        "ponto_admin.html",
        registros=registros,
        secretarias=secretarias,
        filtro_secretaria=secretaria_id,
        filtro_nome=busca_nome or "",
        mes=mes,
        inicio_20=inicio_20,
        inicio_40=inicio_40,
        entrada_2=entrada_2,
        tolerancia_min=tolerancia_min,
        atraso_total_geral_min=atraso_total_geral_min,
        atraso_total_geral_horas=round(atraso_total_geral_min / 60.0, 2),
        resumo_servidores=resumo_servidores,
    )


@app.route("/exportar_migracao")
@login_required
def exportar_migracao():
    funcionarios = Funcionario.query.all()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")

    # Cabeçalho que o Gestor 360 espera ler
    header = [
        "Nº CONTRATO",
        "NOME",
        "CPF",
        "RG",
        "DATA NASCIMENTO",
        "NOME DA MÃE",
        "EMAIL",
        "PIS/PASEP",
        "VÍNCULO",
        "LOCAL",
        "ESCOLA_ID",
        "CLASSE/NÍVEL",
        "Nº CONTRA CHEQUE",
        "NACIONALIDADE",
        "ESTADO CIVIL",
        "TELEFONE",
        "ENDEREÇO",
        "FUNÇÃO",
        "LOTAÇÃO",
        "CARGA HORÁRIA",
        "REMUNERAÇÃO",
        "DADOS BANCÁRIOS",
        "DATA INÍCIO",
        "DATA SAÍDA",
        "OBSERVAÇÕES",
    ]
    writer.writerow(header)

    def formatar_data(dt):
        if not dt:
            return ""
        try:
            return dt.strftime("%Y-%m-%d")
        except:
            return ""

    for f in funcionarios:
        # Garantia contra Erro 404
        contrato = f.num_vinculo if f.num_vinculo else f"MIG-{f.id}"

        # Lógica para Dados Bancários (unindo os campos do seu formulário)
        dados_bancarios = (
            f"Bco: {f.banco}, Ag: {f.agencia}, Cta: {f.conta}" if f.banco else ""
        )

        writer.writerow(
            [
                contrato,  # Nº CONTRATO
                f.nome.upper() if f.nome else "",  # NOME
                f.cpf if f.cpf else "",  # CPF
                f.rg if f.rg else "",  # RG
                formatar_data(f.data_nasc),  # DATA NASCIMENTO (Confirmado: data_nasc)
                f.mae.upper() if f.mae else "",  # NOME DA MÃE (Confirmado: mae)
                f.email if f.email else "",  # EMAIL
                f.pis if f.pis else "",  # PIS/PASEP (Confirmado: pis)
                f.tipo_vinculo if f.tipo_vinculo else "CONTRATADO",  # VÍNCULO
                f.local_trabalho.nome if f.local_trabalho else "SEME",  # LOCAL
                (
                    f.local_trabalho_id if f.local_trabalho_id else ""
                ),  # ESCOLA_ID (Usando local_trabalho_id)
                f.classe if f.classe else "",  # CLASSE/NÍVEL
                f.contracheque if f.contracheque else "",  # Nº CONTRA CHEQUE
                f.nacionalidade if f.nacionalidade else "BRASILEIRA",  # NACIONALIDADE
                f.estado_civil if f.estado_civil else "SOLTEIRO(A)",  # ESTADO CIVIL
                f.telefone if f.telefone else "",  # TELEFONE
                f.endereco.upper() if f.endereco else "",  # ENDEREÇO
                f.funcao.nome if f.funcao else "AUXILIAR",  # FUNÇÃO
                f.lotacao if f.lotacao else "EDUCAÇÃO",  # LOTAÇÃO
                f.jornada_trabalho if f.jornada_trabalho else "40",  # CARGA HORÁRIA
                f.remuneracao if f.remuneracao else "0.00",  # REMUNERAÇÃO
                dados_bancarios,  # DADOS BANCÁRIOS
                formatar_data(f.dt_inicio),  # DATA INÍCIO (Confirmado: dt_inicio)
                formatar_data(f.dt_termino),  # DATA SAÍDA (Confirmado: dt_termino)
                "Migração automática Ficha2026",  # OBSERVAÇÕES
            ]
        )

    output.seek(0)
    return Response(
        output.getvalue().encode("utf-8-sig"),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment;filename=migracao_pronta_gestor360.csv"
        },
    )


@app.route("/admin/movimentar_servidor", methods=["POST"])
@login_required
def movimentar_servidor():
    if not current_user.is_admin:
        flash("Acesso não autorizado.", "error")
        return redirect(url_for("sistema"))

    func_id = request.form.get("funcionario_id")
    nova_funcao_id = request.form.get("nova_funcao_id")
    novo_local_id = request.form.get("novo_local_id")

    funcionario = db.session.get(Funcionario, func_id)

    if not funcionario:
        flash("Funcionário não encontrado.", "error")
        return redirect(url_for("admin_dashboard"))

    mudou_funcao = str(funcionario.funcao_id) != str(nova_funcao_id)
    mudou_local = str(funcionario.local_trabalho_id) != str(novo_local_id)

    if not mudou_funcao and not mudou_local:
        flash("Nenhuma alteração foi feita.", "info")
        return redirect(url_for("admin_dashboard", tab="dados"))

    # Registrar histórico ANTES de mudar
    historico = HistoricoLotacao(
        funcionario_id=funcionario.id,
        antiga_secretaria=(
            funcionario.secretaria.nome if funcionario.secretaria else "N/A"
        ),
        antigo_local=(
            funcionario.local_trabalho.nome if funcionario.local_trabalho else "N/A"
        ),
        antiga_funcao=funcionario.funcao.nome if funcionario.funcao else "N/A",
        quem_mudou_id=current_user.id,
    )
    db.session.add(historico)

    if mudou_funcao:
        funcionario.funcao_id = nova_funcao_id
    if mudou_local:
        funcionario.local_trabalho_id = novo_local_id

    registrar_log("MOVIMENTOU", f"Servidor: {funcionario.nome}")
    db.session.commit()
    flash(f"Servidor {funcionario.nome} movimentado com sucesso!", "success")

    return redirect(url_for("admin_dashboard", tab="dados"))


def processar_pdf_para_excel(pdf_path, output_excel):
    dados = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            table = page.extract_table()
            if table:
                dados.extend(table[1:])

    df = pd.DataFrame(
        dados, columns=["NOME_CPF", "LOTACAO_LOCAL", "FUNCAO_VINCULO", "QUEM_INDICOU"]
    )

    with pd.ExcelWriter(output_excel) as writer:
        for local, group in df.groupby("LOTACAO_LOCAL"):
            group.to_excel(writer, sheet_name=str(local)[:31], index=False)


@app.route("/importar_pdf_para_excel", methods=["GET", "POST"])
@login_required
def importar_pdf_para_excel():
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    if request.method == "POST":
        file = request.files.get("pdf_file")
        if file:
            with pdfplumber.open(file) as pdf:
                todas_linhas = []
                for page in pdf.pages:
                    table = page.extract_table()
                    if table:
                        todas_linhas.extend(table[1:])

            df = pd.DataFrame(
                todas_linhas,
                columns=["NOME_CPF", "LOTACAO_LOCAL", "FUNCAO_VINCULO", "QUEM_INDICOU"],
            )

            output = io.BytesIO()
            with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
                for local, group in df.groupby("LOTACAO_LOCAL"):
                    sheet_name = str(local)[:31].replace("/", "-")
                    group.to_excel(writer, sheet_name=sheet_name, index=False)

            output.seek(0)
            return Response(
                output,
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={
                    "Content-Disposition": "attachment;filename=relatorio_organizado.xlsx"
                },
            )

    return render_template("importar_pdf.html")


@app.route("/importar_pdf", methods=["GET", "POST"])
@login_required
def importar_pdf():
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    if request.method == "POST":
        file = request.files.get("pdf_file")
        if file:
            with pdfplumber.open(file) as pdf:
                texto_paginas = [page.extract_text() for page in pdf.pages]

            dados = []
            padrao_cpf = r"\d{3}\.\d{3}\.\d{3}-\d{2}"

            for texto in texto_paginas:
                if not texto:
                    continue
                linhas = texto.split("\n")
                for i, linha in enumerate(linhas):
                    if re.search(padrao_cpf, linha):
                        nome = linhas[i - 1].strip() if i > 0 else "N/A"
                        cpf = re.search(padrao_cpf, linha).group()

                        local = linhas[i + 1].strip() if i + 1 < len(linhas) else ""
                        funcao = linhas[i + 2].strip() if i + 2 < len(linhas) else ""

                        dados.append([nome, cpf, local, funcao])

            df = pd.DataFrame(dados, columns=["NOME", "CPF", "LOCAL", "FUNCAO"])

            output = io.BytesIO()
            with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
                for local, group in df.groupby("LOCAL"):
                    nome_aba = str(local)[:31].replace("/", "-").replace("*", "")
                    group.to_excel(
                        writer, sheet_name=nome_aba or "SemLocal", index=False
                    )

            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={
                    "Content-Disposition": "attachment;filename=lotoes_organizado.xlsx"
                },
            )

    return render_template("importar_pdf.html")


@app.route("/ponto/<token>", methods=["GET"])
def pagina_ponto(token):
    funcionario = Funcionario.query.filter_by(token_validacao=token).first()
    if not funcionario:
        return render_template(
            "ponto.html",
            funcionario=None,
            erro="Servidor não encontrado ou QRCode inválido.",
        )

    registros = (
        RegistroPonto.query.filter_by(funcionario_id=funcionario.id)
        .order_by(RegistroPonto.data_hora.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "ponto.html", funcionario=funcionario, registros=registros, erro=None
    )


@app.route("/ponto/<token>/registrar", methods=["POST"])
def registrar_ponto(token):
    funcionario = Funcionario.query.filter_by(token_validacao=token).first()
    if not funcionario:
        flash("Servidor não encontrado ou QRCode inválido.", "error")
        return redirect(url_for("pagina_ponto", token=token))

    # --- AJUSTE DE HORÁRIO BRASÍLIA ---
    fuso_br = pytz.timezone('America/Sao_Paulo')
    agora_br = datetime.now(fuso_br).replace(tzinfo=None)

    # Recebe as coordenadas enviadas pelo celular do funcionário
    lat_req = request.form.get("lat")
    lng_req = request.form.get("lng")
    acc = request.form.get("acc") # Precisão do GPS

    # --- INÍCIO DA VALIDAÇÃO DE GEOFENCING ---
    local = funcionario.local_trabalho
    
    if local and local.latitude and local.longitude:
        if not lat_req or not lng_req:
            flash("Localização GPS não capturada. Verifique se o GPS está ativo e se você deu permissão ao navegador.", "error")
            return redirect(url_for("pagina_ponto", token=token))

        try:
            f_lat_req = float(lat_req)
            f_lng_req = float(lng_req)
            f_lat_loc = float(local.latitude)
            f_lng_loc = float(local.longitude)

            distancia_metros = calcular_distancia(f_lat_req, f_lng_req, f_lat_loc, f_lng_loc)
            raio_limite = local.raio_permitido or 50 
            
            print(f"DEBUG PONTO: {funcionario.nome} | Distância: {distancia_metros:.2f}m | Limite: {raio_limite}m")

            if distancia_metros > raio_limite:
                msg_erro = f"FORA DO RAIO: Você está a {int(distancia_metros)}m da unidade. Aproxime-se para bater o ponto (Limite: {raio_limite}m)."
                flash(msg_erro, "error")
                registrar_log("BLOQUEIO_GEOFENCING", f"{funcionario.nome} tentou a {int(distancia_metros)}m")
                return redirect(url_for("pagina_ponto", token=token))
                
        except (ValueError, TypeError) as e:
            print(f"Erro ao calcular distância: {e}")
            flash("Erro ao processar coordenadas de localização.", "error")
            return redirect(url_for("pagina_ponto", token=token))
    else:
        print(f"AVISO: {funcionario.nome} bateu ponto em local sem GPS cadastrado.")

    # --- LÓGICA DE ALTERNÂNCIA E LIMITES COM HORÁRIO CORRETO ---
    hoje_inicio = agora_br.replace(hour=0, minute=0, second=0, microsecond=0)
    hoje_fim = agora_br.replace(hour=23, minute=59, second=59, microsecond=999999)

    registros_hoje = (
        RegistroPonto.query.filter(
            RegistroPonto.funcionario_id == funcionario.id,
            RegistroPonto.data_hora >= hoje_inicio,
            RegistroPonto.data_hora <= hoje_fim,
        )
        .order_by(RegistroPonto.data_hora.desc())
        .all()
    )

    if len(registros_hoje) >= 4:
        flash("Limite diário atingido. Você já registrou 4 batidas hoje.", "error")
        return redirect(url_for("pagina_ponto", token=token))

    ultimo_registro = registros_hoje[0] if registros_hoje else None
    tipo_calculado = "entrada" if not ultimo_registro or ultimo_registro.tipo == "saida" else "saida"

    # --- TRATAMENTO DA FOTO ---
    foto_base64 = request.form.get("foto_base64")
    foto_path_rel = None

    if foto_base64:
        try:
            if "," in foto_base64:
                foto_base64 = foto_base64.split(",", 1)[1]

            foto_bytes = base64.b64decode(foto_base64)
            fotos_dir = os.path.join(app.root_path, "static", "ponto_fotos")
            os.makedirs(fotos_dir, exist_ok=True)
            
            # Nome do arquivo usando o timestamp de Brasília
            filename = f"{funcionario.id}_{agora_br.strftime('%Y%m%d%H%M%S')}.jpg"
            file_path = os.path.join(fotos_dir, filename)
            
            with open(file_path, "wb") as f:
                f.write(foto_bytes)
            foto_path_rel = f"ponto_fotos/{filename}"
        except Exception as e:
            print(f"Erro ao salvar foto: {e}")

    # --- GRAVAÇÃO NO BANCO ---
    try:
        registro = RegistroPonto(
            funcionario_id=funcionario.id,
            data_hora=agora_br, # Salvando com o horário corrigido
            tipo=tipo_calculado,
            latitude=float(lat_req) if lat_req else None,
            longitude=float(lng_req) if lng_req else None,
            precisao=float(acc) if acc else None,
            foto_path=foto_path_rel,
        )
        db.session.add(registro)
        db.session.commit()
        
        registrar_log(f"PONTO_{tipo_calculado.upper()}", funcionario.nome)
        flash(f"Ponto de {tipo_calculado.upper()} registrado com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Erro ao gravar no banco de dados.", "error")
        print(f"Erro ao salvar registro de ponto: {e}")

    return redirect(url_for("pagina_ponto", token=token))


@app.route("/gerar_rescisao_excluir/<int:id>")
@login_required
def gerar_rescisao_excluir(id):
    funcionario = db.session.get(Funcionario, id)
    if not funcionario:
        flash("Funcionário não encontrado", "error")
        return redirect(url_for("sistema"))

    try:
        nova_rescisao = RescisaoHistorico(
            nome=funcionario.nome,
            cpf=funcionario.cpf,
            funcao=funcionario.funcao.nome if funcionario.funcao else "N/A",
            data_inicio=funcionario.dt_inicio,
            data_saida=(
                funcionario.dt_termino if funcionario.dt_termino else date.today()
            ),
        )
        db.session.add(nova_rescisao)

        dados_rescisao = {
            "nome": funcionario.nome,
            "dt_inicio": (
                funcionario.dt_inicio.strftime("%d/%m/%Y")
                if funcionario.dt_inicio
                else "N/D"
            ),
            "dt_termino": (
                funcionario.dt_termino.strftime("%d/%m/%Y")
                if funcionario.dt_termino
                else date.today().strftime("%d/%m/%Y")
            ),
            "funcao_nome": funcionario.funcao.nome if funcionario.funcao else "N/A",
        }

        registrar_log("RESCISAO E EXCLUSAO", funcionario.nome)

        HistoricoLotacao.query.filter_by(funcionario_id=id).delete()
        RegistroPonto.query.filter_by(funcionario_id=id).delete()

        db.session.delete(funcionario)
        db.session.commit()

        meses = [
            "janeiro",
            "fevereiro",
            "março",
            "abril",
            "maio",
            "junho",
            "julho",
            "agosto",
            "setembro",
            "outubro",
            "novembro",
            "dezembro",
        ]
        hoje = datetime.now()
        data_extenso = f"{hoje.day} de {meses[hoje.month - 1]} de {hoje.year}"

        return render_template(
            "recisao.html", funcionario=dados_rescisao, data_atual=data_extenso
        )

    except Exception as e:
        db.session.rollback()
        print(f"Erro ao excluir: {e}")
        flash("Erro ao processar exclusão no banco de dados.", "error")
        return redirect(url_for("sistema"))


########### PONTO ELETRONICO ####################
@app.route("/ponto/registrar_facial", methods=["POST"])
def registrar_ponto_facial():
    cpf_informado = request.form.get("cpf")
    lat = request.form.get("lat")
    lng = request.form.get("lng")
    foto_base64 = request.form.get("foto_base64")
    
    # PEGA O LOCAL ONDE O PONTO ESTÁ SENDO BATIDO (vindo do formulário/QR Code)
    # Usaremos esse ID apenas para o redirecionamento de tela
    local_batida_id = request.form.get("local_id")

    # --- AJUSTE DE HORÁRIO BRASÍLIA ---
    fuso_br = pytz.timezone('America/Sao_Paulo')
    agora_br = datetime.now(fuso_br).replace(tzinfo=None)

    # 1. Identificação do Funcionário
    if cpf_informado:
        cpf_limpo = "".join(filter(str.isdigit, cpf_informado))
        funcionario = Funcionario.query.filter(
            (Funcionario.cpf == cpf_informado) | (Funcionario.cpf == cpf_limpo)
        ).first()
    else:
        id_facial = request.form.get("funcionario_id")
        if not id_facial or id_facial == "" or id_facial == "None":
            flash("Erro: Nenhum servidor identificado. Aguarde o reconhecimento ou use o CPF.", "error")
            return redirect(url_for("ponto_portal", local_id=local_batida_id))
        
        try:
            id_valido = int(id_facial)
            funcionario = db.session.get(Funcionario, id_valido)
        except (ValueError, TypeError):
            flash("Identificação inválida recebida pelo sistema.", "error")
            return redirect(url_for("ponto_portal", local_id=local_batida_id))

    if not funcionario:
        flash("Servidor não localizado. Verifique os dados ou procure o RH.", "error")
        return redirect(url_for("ponto_portal", local_id=local_batida_id))


    # ==============================================================================
    # LÓGICA CORRIGIDA: GEOFENCING BASEADO NA FICHA DO SERVIDOR (A FONTE DA VERDADE)
    # ==============================================================================
    local_de_trabalho_correto = funcionario.local_trabalho
    
    if not local_de_trabalho_correto:
        flash("Acesso Negado: Você não possui um Local de Trabalho configurado na sua ficha.", "error")
        return redirect(url_for("ponto_portal", local_id=local_batida_id))

    # --- VALIDAÇÃO DE GEOFENCING (Fisicamente no local correto) ---
    if local_de_trabalho_correto.latitude and local_de_trabalho_correto.longitude:
        # Evita que erros de digitação bizarros travem o funcionário
        if not (-90 <= local_de_trabalho_correto.latitude <= 90) or not (-180 <= local_de_trabalho_correto.longitude <= 180):
            print(f"AVISO: Coordenadas de '{local_de_trabalho_correto.nome}' inválidas no banco. Ponto liberado.")
        else:
            if not lat or not lng:
                flash("GPS não detectado. Ative a localização para registrar o ponto.", "error")
                return redirect(url_for("ponto_portal", local_id=local_batida_id))
                
            distancia = calcular_distancia(float(lat), float(lng), local_de_trabalho_correto.latitude, local_de_trabalho_correto.longitude)
            raio = local_de_trabalho_correto.raio_permitido or 50
            
            if distancia > raio:
                flash(f"Acesso Negado: Você precisa estar dentro de '{local_de_trabalho_correto.nome}' para bater o ponto.", "error")
                registrar_log("TENTATIVA_FORA_RAIO", f"{funcionario.nome} longe de {local_de_trabalho_correto.nome}")
                return redirect(url_for("ponto_portal", local_id=local_batida_id))
    # ==============================================================================


    # --- LÓGICA DE ALTERNÂNCIA E LIMITES ---
    hoje_inicio = agora_br.replace(hour=0, minute=0, second=0, microsecond=0)
    hoje_fim = agora_br.replace(hour=23, minute=59, second=59, microsecond=999999)

    registros_hoje = (
        RegistroPonto.query.filter(
            RegistroPonto.funcionario_id == funcionario.id,
            RegistroPonto.data_hora >= hoje_inicio,
            RegistroPonto.data_hora <= hoje_fim,
        )
        .order_by(RegistroPonto.data_hora.desc())
        .all()
    )

    if len(registros_hoje) >= 4:
        flash("Limite diário atingido. Você já registrou 4 batidas de ponto hoje.", "error")
        return redirect(url_for("ponto_portal", local_id=local_batida_id))

    tipo_atual = "entrada" if not registros_hoje or registros_hoje[0].tipo == "saida" else "saida"

    # --- SALVAMENTO DA FOTO ---
    foto_path_rel = None
    if foto_base64:
        try:
            if "," in foto_base64:
                foto_base64 = foto_base64.split(",", 1)[1]
            foto_bytes = base64.b64decode(foto_base64)
            fotos_dir = os.path.join(app.root_path, "static", "ponto_fotos")
            os.makedirs(fotos_dir, exist_ok=True)
            filename = f"ponto_{funcionario.id}_{agora_br.strftime('%Y%m%d%H%M%S')}.jpg"
            file_path = os.path.join(fotos_dir, filename)
            with open(file_path, "wb") as f:
                f.write(foto_bytes)
            foto_path_rel = f"ponto_fotos/{filename}"
        except Exception as e:
            print(f"Erro ao salvar foto: {e}")

    # --- GRAVAÇÃO DO REGISTRO ---
    try:
        novo_registro = RegistroPonto(
            funcionario_id=funcionario.id,
            data_hora=agora_br,
            tipo=tipo_atual,
            latitude=float(lat) if lat else None,
            longitude=float(lng) if lng else None,
            foto_path=foto_path_rel,
        )
        db.session.add(novo_registro)
        db.session.commit()

        registrar_log(f"PONTO {tipo_atual.upper()}", f"{funcionario.nome} em {local_de_trabalho_correto.nome}")
        flash(f"Ponto de {tipo_atual.upper()} registrado com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Erro ao gravar no banco de dados.", "error")
        print(f"Erro: {e}")

    return redirect(url_for("ponto_portal", local_id=local_batida_id))


@app.route("/admin/ponto/escola/<int:local_id>")
@login_required
def ponto_por_escola(local_id):
    if not current_user.is_admin:
        return redirect(url_for("sistema"))

    escola = db.session.get(LocalTrabalho, local_id)
    # Filtra apenas servidores vinculados a esta escola
    servidores = (
        Funcionario.query.filter_by(local_trabalho_id=local_id)
        .order_by(Funcionario.nome)
        .all()
    )

    mes_selecionado = request.args.get("mes", datetime.now().strftime("%Y-%m"))

    return render_template(
        "ponto_escola.html", escola=escola, servidores=servidores, mes=mes_selecionado
    )


@app.route("/admin/ponto/gerar_pdf/<int:func_id>")
@login_required
def gerar_relatorio_frequencia(func_id):
    mes_ref = request.args.get("mes", datetime.now().strftime("%Y-%m"))
    ano, mes = map(int, mes_ref.split("-"))

    funcionario = db.session.get(Funcionario, func_id)
    # Busca todos os pontos do servidor no mês
    registros = (
        RegistroPonto.query.filter(
            RegistroPonto.funcionario_id == func_id,
            func.extract("month", RegistroPonto.data_hora) == mes,
            func.extract("year", RegistroPonto.data_hora) == ano,
        )
        .order_by(RegistroPonto.data_hora.asc())
        .all()
    )

    # Organiza os pontos por dia
    pontos_por_dia = {}
    for r in registros:
        dia = r.data_hora.day
        if dia not in pontos_por_dia:
            pontos_por_dia[dia] = []
        pontos_por_dia[dia].append(r)

    # Gera a lista de todos os dias do mês para o relatório
    import calendar

    _, ultimo_dia = calendar.monthrange(ano, mes)

    dias_trabalhados = 0
    dias_faltosos = 0
    folha_mensal = []

    for dia in range(1, ultimo_dia + 1):
        data_atual = date(ano, mes, dia)
        dia_semana = data_atual.weekday()  # 0=Segunda, 6=Domingo

        batidas = pontos_por_dia.get(dia, [])
        status = "PRESENÇA" if batidas else "FALTA"

        # Lógica de Faltas: Se for dia útil (seg a sex) e não tiver batida
        if dia_semana < 5:
            if not batidas:
                dias_faltosos += 1
            else:
                dias_trabalhados += 1

        folha_mensal.append(
            {
                "dia": data_atual.strftime("%d/%m/%Y"),
                "dia_nome": ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"][
                    dia_semana
                ],
                "batidas": batidas,
                "status": status if dia_semana < 5 else "FINAL DE SEMANA",
            }
        )

    return render_template(
        "relatorio_frequencia_pdf.html",
        f=funcionario,
        folha=folha_mensal,
        resumo={
            "trabalhados": dias_trabalhados,
            "faltas": dias_faltosos,
            "mes": mes_ref,
        },
    )


def calcular_distancia(lat1, lon1, lat2, lon2):
    """Calcula a distância em metros entre duas coordenadas de GPS (Haversine)."""
    try:
        R = 6371000  # Raio da Terra em metros
        phi1, phi2 = math.radians(float(lat1)), math.radians(float(lat2))
        delta_phi = math.radians(float(lat2) - float(lat1))
        delta_lambda = math.radians(float(lon2) - float(lon1))
        a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c
    except (TypeError, ValueError):
        return float('inf') # Se der erro matemático, joga distância infinita

@app.route("/admin/salvar_biometria", methods=["POST"])
@login_required
def salvar_biometria():
    if not current_user.is_admin:
        return {"error": "Não autorizado"}, 403
    
    dados = request.json
    funcionario_id = dados.get("id")
    foto_base64 = dados.get("foto")

    funcionario = db.session.get(Funcionario, funcionario_id)
    if funcionario:
        funcionario.foto_biometria = foto_base64
        db.session.commit()
        registrar_log("MAPEAMENTO_FACIAL", funcionario.nome)
        return {"status": "sucesso"}
    return {"error": "Funcionário não encontrado"}, 404


@app.route("/ponto-facial")
def ponto_portal():
    """Página principal do portal de ponto facial/coletivo."""
    # 1. Captura o ID do local vindo da URL (ex: /ponto-facial?local_id=5)
    local_id = request.args.get('local_id')
    
    # 2. Busca todos os locais para alimentar o seletor manual (caso o admin queira mudar)
    locais = LocalTrabalho.query.order_by(LocalTrabalho.nome).all()
    
    # 3. Lógica de filtragem de servidores
    if local_id:
        # Se um local foi identificado pelo QR Code, mostra apenas os servidores daquela unidade
        servidores = Funcionario.query.filter_by(local_trabalho_id=local_id).order_by(Funcionario.nome).all()
        
        # Opcional: Verificar se o local_id existe para evitar erros de banco
        local_atual = db.session.get(LocalTrabalho, local_id)
        if not local_atual:
            flash("Unidade de trabalho não encontrada ou QR Code inválido.", "error")
            # Se o local for inválido, limpa o local_id para não quebrar o formulário
            local_id = None 
            servidores = Funcionario.query.order_by(Funcionario.nome).all()
    else:
        # Se não houver QR Code, carrega todos os servidores (comportamento padrão)
        servidores = Funcionario.query.order_by(Funcionario.nome).all()

    # 4. Retorna o template com os dados necessários
    # local_id_selecionado será usado no formulário hidden no HTML para a trava de segurança
    return render_template(
        "ponto_portal.html", 
        servidores=servidores, 
        locais=locais, 
        local_id_selecionado=local_id
    )

@app.route("/reimprimir_rescisao/<int:id>")
@login_required
def reimprimir_rescisao(id):
    rescisao = db.session.get(RescisaoHistorico, id)
    if not rescisao:
        flash("Registro de rescisão não encontrado.", "error")
        return redirect(url_for("pagina_recisoes"))

    dados_doc = {
        "nome": rescisao.nome,
        "funcao": rescisao.funcao,
        "data_inicio": rescisao.data_inicio,
        "data_saida": rescisao.data_saida,
        "cpf": rescisao.cpf,
        "rg": rescisao.rg,
        "endereco": rescisao.endereco,
        "num_contrato": rescisao.num_contrato
    }

    fuso_br = pytz.timezone('America/Sao_Paulo')
    agora_br = datetime.now(fuso_br).replace(tzinfo=None)

    return render_template(
        "recisao_documento.html", f=dados_doc, data_atual=agora_br
    )

@app.route("/api/salvar_dados_rescisao", methods=["POST"])
@login_required
def api_salvar_dados_rescisao():
    """Rota API para salvar as edições de histórico via AJAX sem recarregar a tela"""
    try:
        data = request.get_json()
        rescisao_id = data.get("id")
        rescisao = db.session.get(RescisaoHistorico, rescisao_id)
        
        if not rescisao:
            return {"success": False, "message": "Registro não encontrado"}, 404
            
        rescisao.rg = data.get("rg")
        rescisao.endereco = data.get("endereco")
        rescisao.num_contrato = data.get("num_contrato")
        
        db.session.commit()
        registrar_log("ATUALIZOU DADOS HISTORICOS RESCISAO", rescisao.nome)
        return {"success": True}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500
    
@app.route('/relatorio-geral')
@login_required # Remova ou altere se não usar flask_login nesse projeto
def relatorio_pessoal():
    # Aqui recuperamos todos os funcionários do banco de dados (exemplo usando SQLAlchemy)
    # Ajuste 'Funcionario' para o nome da sua classe de modelo se for diferente
    funcionarios = Funcionario.query.all() 
    
    return render_template('relatorio_pessoal.html', funcionarios=funcionarios)    

@app.route("/admin/escolas/atalhos")
@login_required
def atalhos_escolas():
    # Busca todas as escolas do banco de dados
    escolas = Escola.query.order_all() 
    return render_template("atalhos_escolas.html", escolas=escolas)

@app.route("/admin/unidades_ponto")
@login_required
def unidades_ponto():
    if not current_user.is_admin:
        return redirect(url_for('sistema'))
    
    # Busca todos os locais de trabalho ordenados por nome
    locais = LocalTrabalho.query.order_by(LocalTrabalho.nome).all()
    return render_template("unidades_ponto.html", locais=locais)


# ==============================================================================
# MÓDULO INDEPENDENTE DE ORGANOGRAMA & QUADRO DE CARGOS DA SECRETARIA
# ==============================================================================

@app.route('/organograma')
@login_required
def organograma_page():
    exercicios = OrganogramaExercicio.query.order_by(OrganogramaExercicio.ano.desc(), OrganogramaExercicio.id.desc()).all()
    
    if not exercicios:
        ano_atual = datetime.now().year
        novo_ex = OrganogramaExercicio(
            ano=ano_atual,
            titulo=f"Quadro de Cargos e Estrutura Organizacional - {ano_atual}",
            ativo=True,
            criado_por_id=current_user.id if hasattr(current_user, 'id') else None
        )
        db.session.add(novo_ex)
        db.session.commit()
        
        no_raiz = OrganogramaNode(
            exercicio_id=novo_ex.id,
            parent_id=None,
            tipo="CARGO_CHEFIA",
            titulo="Secretário(a) Municipal",
            sigla="GABINETE/SEME",
            nivel_hierarquico=1,
            tipo_vinculo_requerido="COMISSIONADO",
            vagas_totais=1
        )
        db.session.add(no_raiz)
        db.session.commit()
        exercicios = [novo_ex]
        
    exercicio_id = request.args.get('exercicio_id', type=int)
    selected_exercicio = None
    if exercicio_id:
        selected_exercicio = OrganogramaExercicio.query.get(exercicio_id)
    if not selected_exercicio:
        selected_exercicio = exercicios[0]

    return render_template('organograma.html', 
                           exercicios=exercicios, 
                           selected_exercicio=selected_exercicio)


@app.route('/api/organograma/tree/<int:exercicio_id>')
@login_required
def api_organograma_tree(exercicio_id):
    exercicio = OrganogramaExercicio.query.get_or_404(exercicio_id)
    nodes = OrganogramaNode.query.filter_by(exercicio_id=exercicio.id).all()
    valid_ids = {n.id for n in nodes}
    
    nodes_data = []
    total_cargos = 0
    total_vagas = 0
    total_ocupadas = 0
    total_vagas_vagas = 0
    custo_total_estimado = 0.0
    
    for n in nodes:
        total_cargos += 1
        total_vagas += (n.vagas_totais or 1)
        
        servidores_ativos = OrganogramaServidor.query.filter_by(node_id=n.id, ativo=True).all()
        qtd_ocupadas = len(servidores_ativos)
        total_ocupadas += qtd_ocupadas
        
        vagas_livres = max(0, (n.vagas_totais or 1) - qtd_ocupadas)
        total_vagas_vagas += vagas_livres
        
        servidores_list = []
        for s in servidores_ativos:
            remun = s.remuneracao_estimada or 0.0
            custo_total_estimado += remun
            servidores_list.append({
                "id": s.id,
                "nome": s.nome_servidor,
                "cpf": s.cpf or "---",
                "matricula": s.matricula_vinculo or "---",
                "tipo_vinculo": s.tipo_vinculo or "COMISSIONADO",
                "portaria_nomeacao": s.portaria_nomeacao or "---",
                "data_nomeacao": s.data_nomeacao.strftime('%d/%m/%Y') if s.data_nomeacao else "---",
                "data_inicio": s.data_inicio.strftime('%d/%m/%Y') if s.data_inicio else "---",
                "remuneracao": remun,
                "foto_url": s.foto_url or ""
            })
            
        status_vaga = "DESOCUPADO"
        if qtd_ocupadas > 0:
            if qtd_ocupadas >= (n.vagas_totais or 1):
                status_vaga = "PREENCHIDO"
            else:
                status_vaga = "PARCIAL"
                
        parent_id_str = str(n.parent_id) if (n.parent_id and n.parent_id in valid_ids) else ""

        nodes_data.append({
            "id": str(n.id),
            "parentId": parent_id_str,
            "title": n.titulo,
            "sigla": n.sigla or "",
            "tipo": n.tipo or "UNIDADE",
            "nivel": n.nivel_hierarquico or 1,
            "tipo_vinculo_requerido": n.tipo_vinculo_requerido or "QUALQUER",
            "vagas_totais": n.vagas_totais or 1,
            "vagas_ocupadas": qtd_ocupadas,
            "vagas_livres": vagas_livres,
            "status_vaga": status_vaga,
            "servidores": servidores_list
        })
        
    taxa_ocupacao = round((total_ocupadas / total_vagas * 100), 1) if total_vagas > 0 else 0
    kpis = {
        "total_cargos": total_cargos,
        "total_vagas": total_vagas,
        "total_ocupadas": total_ocupadas,
        "total_vagas_vagas": total_vagas_vagas,
        "taxa_ocupacao": taxa_ocupacao,
        "custo_total_estimado": custo_total_estimado
    }
    
    historico_db = OrganogramaHistorico.query.filter_by(exercicio_id=exercicio.id).order_by(OrganogramaHistorico.data_hora.desc()).limit(20).all()
    historico_list = [{
        "id": h.id,
        "tipo_evento": h.tipo_evento,
        "descricao": h.descricao,
        "portaria": h.portaria_referencia or "---",
        "usuario": h.usuario_nome or "Sistema",
        "data_hora": h.data_hora.strftime('%d/%m/%Y às %H:%M') if h.data_hora else "---"
    } for h in historico_db]
    
    return {
        "success": True,
        "exercicio": {"id": exercicio.id, "ano": exercicio.ano, "titulo": exercicio.titulo},
        "nodes": nodes_data,
        "kpis": kpis,
        "historico": historico_list
    }


@app.route('/api/organograma/exercicio/salvar', methods=['POST'])
@login_required
def api_organograma_exercicio_salvar():
    try:
        data = request.json or {}
        ano = int(data.get('ano', datetime.now().year))
        titulo = data.get('titulo', f'Quadro de Cargos - Exercício {ano}').strip()
        copiar_de_id = data.get('copiar_de_id')
        
        novo_ex = OrganogramaExercicio(
            ano=ano,
            titulo=titulo,
            ativo=True,
            criado_por_id=current_user.id
        )
        db.session.add(novo_ex)
        db.session.commit()
        
        if copiar_de_id:
            ex_antigo = OrganogramaExercicio.query.get(copiar_de_id)
            if ex_antigo:
                id_map = {}
                old_nodes = OrganogramaNode.query.filter_by(exercicio_id=ex_antigo.id).all()
                for old_n in old_nodes:
                    new_n = OrganogramaNode(
                        exercicio_id=novo_ex.id,
                        tipo=old_n.tipo,
                        titulo=old_n.titulo,
                        sigla=old_n.sigla,
                        nivel_hierarquico=old_n.nivel_hierarquico,
                        tipo_vinculo_requerido=old_n.tipo_vinculo_requerido,
                        vagas_totais=old_n.vagas_totais,
                        ordem=old_n.ordem
                    )
                    db.session.add(new_n)
                    db.session.flush()
                    id_map[old_n.id] = new_n.id
                
                for old_n in old_nodes:
                    if old_n.parent_id and old_n.id in id_map and old_n.parent_id in id_map:
                        new_node_id = id_map[old_n.id]
                        new_node = OrganogramaNode.query.get(new_node_id)
                        new_node.parent_id = id_map[old_n.parent_id]
                db.session.commit()

        hist = OrganogramaHistorico(
            exercicio_id=novo_ex.id,
            tipo_evento="CRIACAO_EXERCICIO",
            descricao=f"Novo Exercício '{titulo}' criado por {current_user.username}.",
            usuario_id=current_user.id,
            usuario_nome=current_user.username
        )
        db.session.add(hist)
        db.session.commit()
        
        return {"success": True, "exercicio_id": novo_ex.id}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route('/api/organograma/exercicio/limpar', methods=['POST'])
@login_required
def api_organograma_exercicio_limpar():
    try:
        data = request.json or {}
        exercicio_id = data.get('exercicio_id')
        if not exercicio_id:
            return {"success": False, "message": "ID do exercício é obrigatório."}, 400

        OrganogramaHistorico.query.filter_by(exercicio_id=exercicio_id).delete(synchronize_session=False)
        
        OrganogramaServidor.query.filter(OrganogramaServidor.node_id.in_(
            db.session.query(OrganogramaNode.id).filter_by(exercicio_id=exercicio_id)
        )).delete(synchronize_session=False)
        
        OrganogramaNode.query.filter_by(exercicio_id=exercicio_id).delete(synchronize_session=False)
        db.session.commit()

        no_raiz = OrganogramaNode(
            exercicio_id=exercicio_id,
            parent_id=None,
            tipo="CARGO_CHEFIA",
            titulo="Secretário(a) Municipal",
            sigla="GABINETE/SEME",
            nivel_hierarquico=1,
            tipo_vinculo_requerido="COMISSIONADO",
            vagas_totais=1
        )
        db.session.add(no_raiz)
        db.session.commit()

        hist = OrganogramaHistorico(
            exercicio_id=exercicio_id,
            node_id=no_raiz.id,
            tipo_evento="EDICAO_NO",
            descricao="Estrutura do exercício limpa pelo usuário. Nó raiz inicial criado.",
            usuario_id=current_user.id if hasattr(current_user, 'id') else None,
            usuario_nome=current_user.username if hasattr(current_user, 'username') else "Sistema"
        )
        db.session.add(hist)
        db.session.commit()

        return {"success": True}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route('/api/organograma/node/salvar', methods=['POST'])
@login_required
def api_organograma_node_salvar():
    try:
        data = request.json or {}
        node_id = data.get('id')
        exercicio_id = data.get('exercicio_id')
        parent_id = data.get('parent_id')
        if parent_id and str(parent_id).strip() != "" and str(parent_id) != "null":
            parent_id = int(parent_id)
        else:
            parent_id = None
            
        titulo = data.get('titulo', '').strip()
        sigla = data.get('sigla', '').strip()
        tipo = data.get('tipo', 'UNIDADE')
        tipo_vinculo = data.get('tipo_vinculo_requerido', 'QUALQUER')
        vagas_totais = int(data.get('vagas_totais', 1) or 1)
        
        if not titulo:
            return {"success": False, "message": "O título do cargo ou unidade é obrigatório."}, 400
            
        nivel_hierarquico = 1
        if parent_id:
            parent_node = OrganogramaNode.query.get(parent_id)
            if parent_node:
                nivel_hierarquico = (parent_node.nivel_hierarquico or 1) + 1

        if node_id:
            node = OrganogramaNode.query.get_or_404(node_id)
            node.titulo = titulo
            node.sigla = sigla
            node.tipo = tipo
            node.parent_id = parent_id
            node.nivel_hierarquico = nivel_hierarquico
            node.tipo_vinculo_requerido = tipo_vinculo
            node.vagas_totais = vagas_totais
            desc = f"Cargo/Unidade '{titulo}' atualizado."
            evento = "EDICAO_NO"
        else:
            node = OrganogramaNode(
                exercicio_id=exercicio_id,
                parent_id=parent_id,
                titulo=titulo,
                sigla=sigla,
                tipo=tipo,
                nivel_hierarquico=nivel_hierarquico,
                tipo_vinculo_requerido=tipo_vinculo,
                vagas_totais=vagas_totais
            )
            db.session.add(node)
            desc = f"Novo Cargo/Unidade '{titulo}' adicionado à estrutura."
            evento = "ADICAO_NO"
            
        db.session.commit()
        
        hist = OrganogramaHistorico(
            exercicio_id=node.exercicio_id,
            node_id=node.id,
            tipo_evento=evento,
            descricao=desc,
            usuario_id=current_user.id if hasattr(current_user, 'id') else None,
            usuario_nome=current_user.username if hasattr(current_user, 'username') else "Sistema"
        )
        db.session.add(hist)
        db.session.commit()
        
        return {"success": True}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route('/api/organograma/node/deletar', methods=['POST'])
@login_required
def api_organograma_node_deletar():
    try:
        data = request.json or {}
        node_id = data.get('node_id')
        node = OrganogramaNode.query.get_or_404(node_id)
        
        filhos = OrganogramaNode.query.filter_by(parent_id=node.id).count()
        if filhos > 0:
            return {"success": False, "message": "Não é possível excluir um item que possui sub-unidades vinculadas. Remova os subordinados primeiro."}, 400
            
        titulo_removido = node.titulo
        exercicio_id = node.exercicio_id
        
        OrganogramaHistorico.query.filter_by(node_id=node.id).update({"node_id": None})
        db.session.delete(node)
        db.session.commit()
        
        hist = OrganogramaHistorico(
            exercicio_id=exercicio_id,
            tipo_evento="REMOCAO_NO",
            descricao=f"Cargo/Unidade '{titulo_removido}' removido do organograma.",
            usuario_id=current_user.id if hasattr(current_user, 'id') else None,
            usuario_nome=current_user.username if hasattr(current_user, 'username') else "Sistema"
        )
        db.session.add(hist)
        db.session.commit()
        
        return {"success": True}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route('/api/organograma/servidor/nomear', methods=['POST'])
@login_required
def api_organograma_servidor_nomear():
    try:
        data = request.json or {}
        node_id = data.get('node_id')
        nome_servidor = data.get('nome_servidor', '').strip()
        cpf = data.get('cpf', '').strip()
        matricula_vinculo = data.get('matricula_vinculo', '').strip()
        tipo_vinculo = data.get('tipo_vinculo', 'COMISSIONADO')
        portaria_nomeacao = data.get('portaria_nomeacao', '').strip() or "S/N"
        data_nomeacao_str = data.get('data_nomeacao')
        data_inicio_str = data.get('data_inicio')
        remuneracao_estimada = float(data.get('remuneracao_estimada', 0.0) or 0.0)
        foto_url = data.get('foto_url', '').strip()
        
        if not node_id or not nome_servidor:
            return {"success": False, "message": "Nome do servidor e cargo são obrigatórios."}, 400
            
        node = OrganogramaNode.query.get_or_404(node_id)
        
        dt_nom = None
        if data_nomeacao_str and str(data_nomeacao_str).strip():
            try:
                dt_nom = datetime.strptime(data_nomeacao_str, '%Y-%m-%d').date()
            except ValueError:
                dt_nom = datetime.now().date()
        else:
            dt_nom = datetime.now().date()

        dt_ini = None
        if data_inicio_str and str(data_inicio_str).strip():
            try:
                dt_ini = datetime.strptime(data_inicio_str, '%Y-%m-%d').date()
            except ValueError:
                dt_ini = dt_nom
        else:
            dt_ini = dt_nom
        
        servidor = OrganogramaServidor(
            node_id=node.id,
            nome_servidor=nome_servidor,
            cpf=cpf,
            matricula_vinculo=matricula_vinculo,
            tipo_vinculo=tipo_vinculo,
            portaria_nomeacao=portaria_nomeacao,
            data_nomeacao=dt_nom,
            data_inicio=dt_ini,
            remuneracao_estimada=remuneracao_estimada,
            foto_url=foto_url,
            ativo=True
        )
        db.session.add(servidor)
        db.session.commit()
        
        desc = f"Servidor(a) {nome_servidor} NOMEADO(A) para o cargo de '{node.titulo}' (Portaria/Ato nº {portaria_nomeacao})."
        hist = OrganogramaHistorico(
            exercicio_id=node.exercicio_id,
            node_id=node.id,
            servidor_id=servidor.id,
            tipo_evento="NOMEACAO",
            descricao=desc,
            portaria_referencia=portaria_nomeacao,
            usuario_id=current_user.id if hasattr(current_user, 'id') else None,
            usuario_nome=current_user.username if hasattr(current_user, 'username') else "Sistema"
        )
        db.session.add(hist)
        db.session.commit()
        
        return {"success": True}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route('/api/organograma/servidor/exonerar', methods=['POST'])
@login_required
def api_organograma_servidor_exonerar():
    try:
        data = request.json or {}
        servidor_id = data.get('servidor_id')
        portaria_exoneracao = data.get('portaria_exoneracao', '').strip()
        data_exoneracao_str = data.get('data_exoneracao')
        motivo_exoneracao = data.get('motivo_exoneracao', 'Exoneração a Pedido / Ofício').strip()
        
        if not servidor_id:
            return {"success": False, "message": "ID do servidor é obrigatório."}, 400
            
        if not portaria_exoneracao:
            return {"success": False, "message": "A Portaria de Exoneração é OBRIGATÓRIA para desligar/exonerar um servidor do quadro."}, 400
            
        servidor = OrganogramaServidor.query.get_or_404(servidor_id)
        node = OrganogramaNode.query.get(servidor.node_id)
        
        dt_exo = datetime.strptime(data_exoneracao_str, '%Y-%m-%d').date() if data_exoneracao_str else datetime.now().date()
        
        servidor.ativo = False
        servidor.portaria_exoneracao = portaria_exoneracao
        servidor.data_exoneracao = dt_exo
        servidor.motivo_exoneracao = motivo_exoneracao
        db.session.commit()
        
        desc = f"Servidor(a) {servidor.nome_servidor} EXONERADO(A) do cargo de '{node.titulo if node else '---'}' mediante a Portaria de Exoneração nº {portaria_exoneracao}. Motivo: {motivo_exoneracao}."
        hist = OrganogramaHistorico(
            exercicio_id=node.exercicio_id if node else 1,
            node_id=node.id if node else None,
            servidor_id=servidor.id,
            tipo_evento="EXONERACAO",
            descricao=desc,
            portaria_referencia=portaria_exoneracao,
            usuario_id=current_user.id,
            usuario_nome=current_user.username
        )
        db.session.add(hist)
        db.session.commit()
        
        return {"success": True}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route('/api/organograma/servidor/substituir', methods=['POST'])
@login_required
def api_organograma_servidor_substituir():
    try:
        data = request.json or {}
        servidor_antigo_id = data.get('servidor_antigo_id')
        portaria_exoneracao = data.get('portaria_exoneracao', '').strip()
        data_exoneracao_str = data.get('data_exoneracao')
        motivo_exoneracao = data.get('motivo_exoneracao', 'Substituição no Cargo').strip()
        
        nome_novo_servidor = data.get('nome_novo_servidor', '').strip()
        cpf_novo = data.get('cpf_novo', '').strip()
        matricula_novo = data.get('matricula_novo', '').strip()
        tipo_vinculo_novo = data.get('tipo_vinculo_novo', 'COMISSIONADO')
        portaria_nomeacao = data.get('portaria_nomeacao', '').strip()
        data_nomeacao_str = data.get('data_nomeacao')
        remuneracao_estimada = float(data.get('remuneracao_estimada', 0.0) or 0.0)
        foto_url_novo = data.get('foto_url_novo', '').strip()
        
        if not servidor_antigo_id or not nome_novo_servidor:
            return {"success": False, "message": "Preencha os dados do servidor antigo e do novo servidor."}, 400
            
        if not portaria_exoneracao:
            return {"success": False, "message": "A Portaria de Exoneração do antigo ocupante é OBRIGATÓRIA."}, 400
            
        if not portaria_nomeacao:
            return {"success": False, "message": "A Portaria de Nomeação do novo servidor é OBRIGATÓRIA."}, 400
            
        servidor_antigo = OrganogramaServidor.query.get_or_404(servidor_antigo_id)
        node = OrganogramaNode.query.get_or_404(servidor_antigo.node_id)
        dt_exo = datetime.strptime(data_exoneracao_str, '%Y-%m-%d').date() if data_exoneracao_str else datetime.now().date()
        
        servidor_antigo.ativo = False
        servidor_antigo.portaria_exoneracao = portaria_exoneracao
        servidor_antigo.data_exoneracao = dt_exo
        servidor_antigo.motivo_exoneracao = motivo_exoneracao
        
        dt_nom = datetime.strptime(data_nomeacao_str, '%Y-%m-%d').date() if data_nomeacao_str else datetime.now().date()
        
        novo_servidor = OrganogramaServidor(
            node_id=node.id,
            nome_servidor=nome_novo_servidor,
            cpf=cpf_novo,
            matricula_vinculo=matricula_novo,
            tipo_vinculo=tipo_vinculo_novo,
            portaria_nomeacao=portaria_nomeacao,
            data_nomeacao=dt_nom,
            data_inicio=dt_nom,
            remuneracao_estimada=remuneracao_estimada,
            foto_url=foto_url_novo,
            ativo=True
        )
        db.session.add(novo_servidor)
        db.session.commit()
        
        desc = f"SUBSTITUIÇÃO DE CARGO em '{node.titulo}': Servidor(a) {servidor_antigo.nome_servidor} EXONERADO(A) (Portaria nº {portaria_exoneracao}) e Servidor(a) {nome_novo_servidor} NOMEADO(A) (Portaria nº {portaria_nomeacao})."
        hist = OrganogramaHistorico(
            exercicio_id=node.exercicio_id,
            node_id=node.id,
            servidor_id=novo_servidor.id,
            tipo_evento="SUBSTITUICAO",
            descricao=desc,
            portaria_referencia=f"Exo: {portaria_exoneracao} / Nom: {portaria_nomeacao}",
            usuario_id=current_user.id,
            usuario_nome=current_user.username
        )
        db.session.add(hist)
        db.session.commit()
        
        return {"success": True}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route('/organograma/exportar/excel/<int:exercicio_id>')
@login_required
def organograma_exportar_excel(exercicio_id):
    exercicio = OrganogramaExercicio.query.get_or_404(exercicio_id)
    nodes = OrganogramaNode.query.filter_by(exercicio_id=exercicio.id).all()
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    
    writer.writerow(['EXERCÍCIO', 'SIGLA', 'UNIDADE / CARGO', 'TIPO', 'TIPO VÍNCULO REQUERIDO', 'VAGAS PREVISTAS', 'SERVIDORES NOMEADOS', 'PORTARIA NOMEAÇÃO', 'DATA NOMEAÇÃO', 'STATUS'])
    
    for n in nodes:
        servidores_ativos = OrganogramaServidor.query.filter_by(node_id=n.id, ativo=True).all()
        if servidores_ativos:
            for s in servidores_ativos:
                writer.writerow([
                    exercicio.ano,
                    n.sigla or '',
                    n.titulo,
                    n.tipo,
                    n.tipo_vinculo_requerido,
                    n.vagas_totais,
                    s.nome_servidor,
                    s.portaria_nomeacao or '',
                    s.data_nomeacao.strftime('%d/%m/%Y') if s.data_nomeacao else '',
                    'OCUPADO'
                ])
        else:
            writer.writerow([
                exercicio.ano,
                n.sigla or '',
                n.titulo,
                n.tipo,
                n.tipo_vinculo_requerido,
                n.vagas_totais,
                'VAGO / DESOCUPADO',
                '---',
                '---',
                'VAGO'
            ])
            
    output.seek(0)
    filename = f"quadro_cargos_organograma_{exercicio.ano}.csv"
    return Response(
        output.getvalue().encode('utf-8-sig'),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )


@app.route('/api/organograma/buscar_funcionarios')
@login_required
def api_organograma_buscar_funcionarios():
    q = request.args.get('q', '').strip()
    query = Funcionario.query
    if q:
        query = query.filter(
            db.or_(
                Funcionario.nome.ilike(f"%{q}%"),
                Funcionario.cpf.ilike(f"%{q}%"),
                Funcionario.num_vinculo.ilike(f"%{q}%")
            )
        )
    funcionarios = query.limit(20).all()
    results = []
    for f in funcionarios:
        results.append({
            "id": f.id,
            "nome": f.nome,
            "cpf": f.cpf or "",
            "matricula": f.num_vinculo or "",
            "tipo_vinculo": f.tipo_vinculo or "COMISSIONADO",
            "remuneracao": str(f.remuneracao or "0.00"),
            "foto_url": f.foto_path or ""
        })
    return {"success": True, "funcionarios": results}


@app.route('/organograma/pdf/<int:exercicio_id>')
@login_required
def organograma_pdf_view(exercicio_id):
    exercicio = OrganogramaExercicio.query.get_or_404(exercicio_id)
    nodes = OrganogramaNode.query.filter_by(exercicio_id=exercicio.id).order_by(OrganogramaNode.nivel_hierarquico, OrganogramaNode.ordem, OrganogramaNode.id).all()
    valid_ids = {n.id for n in nodes}
    
    nodes_by_id = {}
    nodes_quadro = []
    servidores_list = []
    
    total_cargos = 0
    total_vagas = 0
    total_ocupadas = 0
    total_vagas_vagas = 0
    custo_total_estimado = 0.0

    for n in nodes:
        total_cargos += 1
        v_tot = n.vagas_totais or 1
        total_vagas += v_tot
        
        servidores_ativos = OrganogramaServidor.query.filter_by(node_id=n.id, ativo=True).all()
        qtd_ocupadas = len(servidores_ativos)
        total_ocupadas += qtd_ocupadas
        vagas_livres = max(0, v_tot - qtd_ocupadas)
        total_vagas_vagas += vagas_livres
        
        servidor_nome = servidores_ativos[0].nome_servidor if servidores_ativos else "VAGA"
        is_vaga = len(servidores_ativos) == 0
        parent_id = n.parent_id if (n.parent_id and n.parent_id in valid_ids) else None
        
        for s in servidores_ativos:
            remun = s.remuneracao_estimada or 0.0
            custo_total_estimado += remun
            servidores_list.append({
                "id": s.id,
                "nome": s.nome_servidor,
                "cpf": s.cpf or "---",
                "cargo_titulo": n.titulo,
                "tipo_vinculo": s.tipo_vinculo or "COMISSIONADO",
                "portaria_nomeacao": s.portaria_nomeacao or "---",
                "data_nomeacao": s.data_nomeacao.strftime('%d/%m/%Y') if s.data_nomeacao else "---",
                "remuneracao": remun
            })
            
        nodes_quadro.append({
            "sigla": n.sigla or "---",
            "titulo": n.titulo,
            "tipo": n.tipo or "UNIDADE",
            "tipo_vinculo_requerido": n.tipo_vinculo_requerido or "QUALQUER",
            "vagas_totais": v_tot,
            "vagas_ocupadas": qtd_ocupadas,
            "vagas_livres": vagas_livres,
            "status": "PREENCHIDO" if vagas_livres == 0 else "VAGO"
        })
        
        nodes_by_id[n.id] = {
            "id": n.id,
            "parent_id": parent_id,
            "titulo": n.titulo,
            "sigla": n.sigla or "",
            "nivel": n.nivel_hierarquico or 1,
            "tipo": n.tipo,
            "servidor_nome": servidor_nome,
            "is_vaga": is_vaga,
            "children": []
        }

    root_nodes = []
    for node_id, node_data in nodes_by_id.items():
        p_id = node_data["parent_id"]
        if p_id and p_id in nodes_by_id:
            nodes_by_id[p_id]["children"].append(node_data)
        else:
            root_nodes.append(node_data)

    taxa_ocupacao = round((total_ocupadas / total_vagas * 100), 1) if total_vagas > 0 else 0
    kpis = {
        "total_cargos": total_cargos,
        "total_vagas": total_vagas,
        "total_ocupadas": total_ocupadas,
        "total_vagas_vagas": total_vagas_vagas,
        "taxa_ocupacao": taxa_ocupacao,
        "custo_total_estimado": custo_total_estimado
    }
    
    historico_db = OrganogramaHistorico.query.filter_by(exercicio_id=exercicio.id).order_by(OrganogramaHistorico.data_hora.desc()).limit(30).all()
    historico_list = [{
        "data_hora": h.data_hora.strftime('%d/%m/%Y às %H:%M') if h.data_hora else "---",
        "tipo_evento": h.tipo_evento,
        "descricao": h.descricao,
        "portaria": h.portaria_referencia or "---",
        "usuario": h.usuario_nome or "Sistema"
    } for h in historico_db]

    data_hoje = datetime.now().strftime('%d/%m/%Y às %H:%M')
    return render_template(
        'organograma_pdf.html',
        exercicio=exercicio,
        root_nodes=root_nodes,
        nodes_quadro=nodes_quadro,
        servidores_list=servidores_list,
        historico_list=historico_list,
        kpis=kpis,
        data_hoje=data_hoje,
        datetime=datetime
    )


# =========================================================================
# MÓDULO: PORTAL DO SERVIDOR - ATESTADOS MÉDICOS & JUSTIFICATIVAS DE FALTAS
# =========================================================================

def extrair_dados_ocr_atestado(file_bytes, filename):
    resultado = {"crm": None, "cid": None, "dias": None}
    if not file_bytes:
        return resultado

    texto_extraido = ""
    ext = (filename or "").split(".")[-1].lower()

    if ext == "pdf":
        try:
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                for page in pdf.pages:
                    txt = page.extract_text()
                    if txt:
                        texto_extraido += txt + "\n"
        except Exception as e:
            print("Erro ao ler PDF no OCR:", e)

    if texto_extraido:
        # Busca CRM: CRM/PI 12345, CRM 12345, CRM-PI 12345
        match_crm = re.search(r'(?:CRM|crm)[\s/:\.\-]*([A-Z]{2})?[\s/:\.\-]*(\d{3,7})', texto_extraido)
        if match_crm:
            uf = match_crm.group(1) or ""
            num = match_crm.group(2)
            resultado["crm"] = f"CRM{'/' + uf.upper() if uf else ''} {num}"

        # Busca CID: Z00, Z00.0, J11, B34.9
        match_cid = re.search(r'\b([A-Z]\d{2}(?:\.\d{1,2})?)\b', texto_extraido)
        if match_cid:
            resultado["cid"] = match_cid.group(1)

        # Busca Dias: 15 dias, 3 (três) dias
        match_dias = re.search(r'(\d+)\s*(?:dias|dia)', texto_extraido, re.IGNORECASE)
        if match_dias:
            try:
                resultado["dias"] = int(match_dias.group(1))
            except Exception:
                pass

    return resultado


@app.route("/portal/servidor/login", methods=["GET", "POST"])
def portal_servidor_login():
    if session.get("servidor_id"):
        return redirect(url_for("portal_servidor_dashboard"))

    if request.method == "POST":
        cpf_raw = request.form.get("cpf", "").strip()
        data_nasc_raw = request.form.get("data_nasc", "").strip()

        cpf_clean = re.sub(r"\D", "", cpf_raw)
        if not cpf_clean:
            flash("Informe um CPF válido para login.", "danger")
            return redirect(url_for("portal_servidor_login"))

        # Busca funcionario por CPF
        funcionarios = Funcionario.query.all()
        funcionario = None
        for f in funcionarios:
            if f.cpf and re.sub(r"\D", "", f.cpf) == cpf_clean:
                funcionario = f
                break

        if not funcionario:
            flash("CPF não encontrado no cadastro do município. Procure o RH da Secretaria.", "danger")
            return redirect(url_for("portal_servidor_login"))

        # Validação da Data de Nascimento (Senha)
        if not funcionario.data_nasc:
            flash("Data de nascimento não cadastrada para este servidor. Contate o RH.", "danger")
            return redirect(url_for("portal_servidor_login"))

        dt_nasc_valida = False
        data_nasc_clean = re.sub(r"\D", "", data_nasc_raw)

        # Formatos aceitos: DD/MM/AAAA ou YYYY-MM-DD
        dt_func_str1 = funcionario.data_nasc.strftime("%d/%m/%Y")
        dt_func_str2 = funcionario.data_nasc.strftime("%Y-%m-%d")
        dt_func_clean = funcionario.data_nasc.strftime("%d%m%Y")

        if data_nasc_raw in (dt_func_str1, dt_func_str2) or data_nasc_clean == dt_func_clean:
            dt_nasc_valida = True

        if not dt_nasc_valida:
            flash("Data de nascimento (senha) incorreta. Tente no formato DD/MM/AAAA.", "danger")
            return redirect(url_for("portal_servidor_login"))

        # Login com sucesso na sessão do servidor
        session["servidor_id"] = funcionario.id
        session["servidor_nome"] = funcionario.nome
        session["servidor_cpf"] = funcionario.cpf
        flash(f"Bem-vindo(a), {funcionario.nome}!", "success")
        return redirect(url_for("portal_servidor_dashboard"))

    return render_template("portal_servidor_login.html")


@app.route("/portal/servidor/dashboard")
def portal_servidor_dashboard():
    servidor_id = session.get("servidor_id")
    if not servidor_id:
        return redirect(url_for("portal_servidor_login"))

    funcionario = Funcionario.query.get(servidor_id)
    if not funcionario:
        session.pop("servidor_id", None)
        return redirect(url_for("portal_servidor_login"))

    justificativas = JustificativaFalta.query.filter_by(funcionario_id=funcionario.id).order_by(JustificativaFalta.data_solicitacao.desc()).all()
    return render_template("portal_servidor_dashboard.html", funcionario=funcionario, justificativas=justificativas)


@app.route("/portal/servidor/justificativa/nova")
def portal_servidor_justificativa_nova():
    if not session.get("servidor_id"):
        return redirect(url_for("portal_servidor_login"))
    return render_template("portal_servidor_justificativa.html")


@app.route("/portal/servidor/justificativa/salvar", methods=["POST"])
def portal_servidor_justificativa_salvar():
    servidor_id = session.get("servidor_id")
    if not servidor_id:
        return redirect(url_for("portal_servidor_login"))

    funcionario = Funcionario.query.get(servidor_id)
    if not funcionario:
        return redirect(url_for("portal_servidor_login"))

    motivo = request.form.get("motivo_ausencia", "").strip()
    dt_inicio_str = request.form.get("data_inicio_afastamento", "").strip()
    dias_str = request.form.get("dias_solicitados", "1").strip()

    if not motivo:
        flash("O motivo da ausência é obrigatório.", "danger")
        return redirect(url_for("portal_servidor_justificativa_nova"))

    dt_inicio = None
    if dt_inicio_str:
        try:
            dt_inicio = datetime.strptime(dt_inicio_str, "%Y-%m-%d").date()
        except ValueError:
            pass

    try:
        dias_req = int(dias_str)
    except ValueError:
        dias_req = 1

    file = request.files.get("anexo")
    anexo_b64 = None
    ext = None
    ocr_res = {"crm": None, "cid": None, "dias": None}

    if file and file.filename:
        file_bytes = file.read()
        if file_bytes:
            anexo_b64 = base64.b64encode(file_bytes).decode("utf-8")
            ext = file.filename.split(".")[-1].lower() if "." in file.filename else "jpg"
            ocr_res = extrair_dados_ocr_atestado(file_bytes, file.filename)

    # Gera Protocolo Único
    ano_atual = datetime.now().year
    protocolo = f"JUST-{ano_atual}-{str(uuid.uuid4().hex[:6]).upper()}"

    just = JustificativaFalta(
        protocolo=protocolo,
        funcionario_id=funcionario.id,
        secretaria_id=funcionario.secretaria_id,
        motivo_ausencia=motivo,
        data_inicio_afastamento=dt_inicio,
        dias_solicitados=dias_req,
        anexo_base64=anexo_b64,
        extensao_anexo=ext,
        crm_medico_ocr=ocr_res.get("crm"),
        cid_ocr=ocr_res.get("cid"),
        dias_atestado_ocr=ocr_res.get("dias"),
        status="PENDENTE"
    )

    db.session.add(just)
    db.session.commit()

    flash(f"Justificativa enviada com sucesso! Seu número de protocolo é {protocolo}.", "success")
    return redirect(url_for("portal_servidor_dashboard"))


@app.route("/portal/servidor/atestado/download/<int:id>")
def portal_servidor_download_atestado(id):
    just = JustificativaFalta.query.get_or_404(id)

    # Autorização: servidor dono da solicitação ou usuário admin/rh autenticado
    is_owner = session.get("servidor_id") == just.funcionario_id
    is_rh = current_user.is_authenticated

    if not (is_owner or is_rh):
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for("portal_servidor_login"))

    if not just.anexo_base64:
        flash("Anexo não disponível.", "danger")
        return redirect(url_for("portal_servidor_dashboard"))

    try:
        file_data = base64.b64decode(just.anexo_base64)
        mimetype = "application/pdf" if just.extensao_anexo == "pdf" else f"image/{just.extensao_anexo or 'jpeg'}"
        return Response(file_data, mimetype=mimetype)
    except Exception as e:
        print("Erro ao decodificar anexo base64:", e)
        flash("Erro ao abrir anexo.", "danger")
        return redirect(url_for("portal_servidor_dashboard"))


@app.route("/portal/servidor/logout")
def portal_servidor_logout():
    session.pop("servidor_id", None)
    session.pop("servidor_nome", None)
    session.pop("servidor_cpf", None)
    flash("Sessão encerrada com sucesso.", "success")
    return redirect(url_for("portal_servidor_login"))


# === ROTAS DE ADMIN/RH PARA GESTÃO DE ATESTADOS ===

@app.route("/admin/atestados")
@login_required
def admin_atestados():
    status_filter = request.args.get("status", "TODOS").upper()
    search = request.args.get("search", "").strip()

    query = JustificativaFalta.query

    # Filtra por secretaria se o usuário não for super admin
    if not (current_user.is_admin or getattr(current_user, "role", "") == "admin"):
        if current_user.secretaria_id:
            query = query.filter_by(secretaria_id=current_user.secretaria_id)

    if status_filter in ("PENDENTE", "APROVADO", "REJEITADO"):
        query = query.filter_by(status=status_filter)

    if search:
        search_like = f"%{search}%"
        query = query.join(Funcionario).filter(
            (Funcionario.nome.ilike(search_like)) |
            (Funcionario.cpf.ilike(search_like)) |
            (JustificativaFalta.protocolo.ilike(search_like))
        )

    justificativas = query.order_by(JustificativaFalta.data_solicitacao.desc()).all()

    # Estatísticas KPI
    base_query = JustificativaFalta.query
    if not (current_user.is_admin or getattr(current_user, "role", "") == "admin"):
        if current_user.secretaria_id:
            base_query = base_query.filter_by(secretaria_id=current_user.secretaria_id)

    total_qtd = base_query.count()
    pendentes_qtd = base_query.filter_by(status="PENDENTE").count()
    aprovados_qtd = base_query.filter_by(status="APROVADO").count()
    rejeitados_qtd = base_query.filter_by(status="REJEITADO").count()

    return render_template(
        "admin_atestados.html",
        justificativas=justificativas,
        total_qtd=total_qtd,
        pendentes_qtd=pendentes_qtd,
        aprovados_qtd=aprovados_qtd,
        rejeitados_qtd=rejeitados_qtd,
        current_status=status_filter,
        search_query=search
    )


@app.route("/api/atestados/aprovar", methods=["POST"])
@login_required
def api_atestados_aprovar():
    data = request.get_json() or {}
    just_id = data.get("id")
    dias_liberados = data.get("dias_liberados", 1)
    obs = data.get("observacao", "").strip()

    if not just_id:
        return jsonify({"success": False, "message": "ID do atestado não fornecido."})

    just = JustificativaFalta.query.get(just_id)
    if not just:
        return jsonify({"success": False, "message": "Solicitação não encontrada."})

    try:
        dias_val = int(dias_liberados)
    except ValueError:
        dias_val = just.dias_solicitados

    just.status = "APROVADO"
    just.dias_liberados_municipio = dias_val
    just.observacao_rh = obs
    just.analisado_por_id = current_user.id
    just.data_analise = datetime.utcnow()

    # Log de auditoria
    log = LogAuditoria(
        usuario_id=current_user.id,
        acao=f"Aprovou Atestado/Justificativa (Protocolo {just.protocolo})",
        alvo=f"Servidor: {just.funcionario.nome} | Dias Liberados: {dias_val}",
        secretaria_id=just.secretaria_id
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({"success": True, "message": "Solicitação Aprovada com Sucesso!"})


@app.route("/api/atestados/reprovar", methods=["POST"])
@login_required
def api_atestados_reprovar():
    data = request.get_json() or {}
    just_id = data.get("id")
    motivo = data.get("motivo_rejeicao", "").strip()

    if not just_id:
        return jsonify({"success": False, "message": "ID do atestado não fornecido."})

    if not motivo:
        return jsonify({"success": False, "message": "O motivo do indeferimento é OBRIGATÓRIO!"})

    just = JustificativaFalta.query.get(just_id)
    if not just:
        return jsonify({"success": False, "message": "Solicitação não encontrada."})

    just.status = "REJEITADO"
    just.motivo_rejeicao = motivo
    just.analisado_por_id = current_user.id
    just.data_analise = datetime.utcnow()

    # Log de auditoria
    log = LogAuditoria(
        usuario_id=current_user.id,
        acao=f"Indeferiu Atestado/Justificativa (Protocolo {just.protocolo})",
        alvo=f"Servidor: {just.funcionario.nome} | Motivo: {motivo}",
        secretaria_id=just.secretaria_id
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({"success": True, "message": "Solicitação Indeferida com Sucesso!"})


# === APENAS UM BLOCO DE EXECUÇÃO NO FINAL DO ARQUIVO ===
# --- 1. EXECUTA TANTO LOCALMENTE QUANTO NO RAILWAY (GUNICORN) ---
with app.app_context():
    db.create_all()
    atualizar_schema()
    create_admin()

# --- 2. EXECUTA APENAS NO SEU COMPUTADOR (LOCAL) ---
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")