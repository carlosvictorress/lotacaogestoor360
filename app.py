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
from datetime import datetime, timedelta, date
import sqlite3
import json
import hmac
import secrets

from flask import Flask, render_template, request, redirect, url_for, flash, Response, has_request_context, session, jsonify, send_file
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
from sqlalchemy import func, text, event
import backup_service
import security

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "chave_secreta_local")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(
    os.getenv("RAILWAY_ENVIRONMENT")
    or os.getenv("RAILWAY_STATIC_URL")
    or os.getenv("FLASK_ENV") == "production"
)

@app.before_request
def security_before_request():
    # 1. Mantém sessão ativa e bloqueia contas desativadas imediatamente
    if current_user and current_user.is_authenticated:
        if getattr(current_user, "ativo", True) is False:
            logout_user()
            flash("Sua conta foi desativada pelo administrador.", "error")
            return redirect(url_for("login"))
        session.permanent = True
        session.modified = True

    # 2. Validação CSRF global para requisições mutáveis autenticadas
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not security.is_csrf_exempt(request.path):
            # Exige CSRF em todas as rotas autenticadas (e no /login quando já há sessão CSRF)
            needs_csrf = current_user.is_authenticated or (
                request.path == "/login" and bool(session.get("_csrf_token"))
            )
            if needs_csrf and not security.validate_csrf_request():
                is_api = request.path.startswith("/api/") or request.is_json
                if is_api:
                    return jsonify({
                        "success": False,
                        "message": "Token de segurança (CSRF) inválido ou expirado. Recarregue a página.",
                    }), 400
                flash("Sessão de formulário expirada (CSRF). Tente novamente.", "error")
                return redirect(request.referrer or url_for("index"))


@app.after_request
def security_after_request(response):
    response = security.apply_security_headers(response)
    # Injeta meta csrf-token + script automático em páginas HTML sem quebrar templates legados
    try:
        ct = response.content_type or ""
        if (
            ct.startswith("text/html")
            and response.status_code == 200
            and not response.direct_passthrough
        ):
            html = response.get_data(as_text=True)
            if "</head>" in html and "security_csrf.js" not in html:
                token = security.get_csrf_token()
                inject = (
                    f'\n    <meta name="csrf-token" content="{token}">'
                    f'\n    <script src="/static/js/security_csrf.js"></script>\n</head>'
                )
                html = html.replace("</head>", inject, 1)
                response.set_data(html)
    except Exception:
        pass
    return response

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
    sigla = db.Column(db.String(20), nullable=True)
    cnpj = db.Column(db.String(25), nullable=True)
    endereco = db.Column(db.String(255), nullable=True)
    telefone = db.Column(db.String(30), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    secretario_nome = db.Column(db.String(150), nullable=True)
    secretario_cargo = db.Column(db.String(120), nullable=True)
    secretario_cpf = db.Column(db.String(30), nullable=True)
    secretario_portaria = db.Column(db.String(100), nullable=True)
    teto_comissionados = db.Column(db.Integer, default=0)
    teto_folha_mensal = db.Column(db.Float, default=0.0)
    ativa = db.Column(db.Boolean, default=True)

    usuarios = db.relationship("User", backref="secretaria", lazy=True)
    funcionarios = db.relationship("Funcionario", backref="secretaria", lazy=True)
    locais = db.relationship("LocalTrabalho", backref="secretaria", lazy=True)


class Funcao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)


class LocalTrabalho(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    secretaria_id = db.Column(db.Integer, db.ForeignKey("secretaria.id"), nullable=True)
    tipo_unidade = db.Column(db.String(40), default="UNIDADE")
    ativa = db.Column(db.Boolean, default=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    raio_permitido = db.Column(db.Integer, default=50)


class Padrinho(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), unique=True, nullable=False)

    @property
    def indicados_count(self):
        return len(self.indicados)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    nome_completo = db.Column(db.String(150), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(
        db.String(40), default="rh_secretaria"
    )  # super_admin, prefeito, estrategia_eleitoral, auditor, secretario, rh_secretaria, chefe_unidade
    secretaria_id = db.Column(db.Integer, db.ForeignKey("secretaria.id"), nullable=True)
    local_trabalho_id = db.Column(db.Integer, db.ForeignKey("local_trabalho.id"), nullable=True)
    local_trabalho = db.relationship("LocalTrabalho", foreign_keys=[local_trabalho_id])
    ativo = db.Column(db.Boolean, default=True)
    tentativas_falhas = db.Column(db.Integer, default=0)
    bloqueado_ate = db.Column(db.DateTime, nullable=True)
    ultimo_login_em = db.Column(db.DateTime, nullable=True)
    ultimo_login_ip = db.Column(db.String(50), nullable=True)
    precisa_trocar_senha = db.Column(db.Boolean, default=False)
    termo_aceito = db.Column(db.Boolean, default=False)
    termo_aceito_em = db.Column(db.DateTime, nullable=True)
    pergunta_troca_senha_exibida = db.Column(db.Boolean, default=False)

    @property
    def is_active(self):
        return bool(True if self.ativo is None else self.ativo)

    @property
    def normalized_role(self):
        return security.normalize_role(self)

    @property
    def role_label(self):
        return security.get_role_label(self)

    @property
    def is_global_scope(self):
        return security.has_global_scope(self)

    def has_perm(self, perm):
        return security.has_permission(self, perm)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class LogAuditoria(db.Model):
    __tablename__ = 'log_auditoria' # Garante o nome correto no banco
    
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    usuario = db.relationship("User", backref="logs")
    secretaria_id = db.Column(db.Integer, nullable=True)
    nivel = db.Column(db.String(20), default="INFO")
    
    # --- CAMPOS ORIGINAIS (MANTIDOS INTACTOS) ---
    acao = db.Column(db.String(255), nullable=False)
    alvo = db.Column(db.String(500), nullable=False)
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
    ativo = db.Column(db.Boolean, default=True)
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

    # --- CAMPOS DE PERFORMANCE & FINANCEIRO (v2027) ---
    cpf_limpo = db.Column(db.String(11), index=True, nullable=True)
    remuneracao_valor = db.Column(db.Float, default=0.0)


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
    secretaria_id = db.Column(db.Integer, db.ForeignKey("secretaria.id"), nullable=True)
    secretaria = db.relationship("Secretaria", foreign_keys=[secretaria_id])
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
    secretaria_id = db.Column(db.Integer, db.ForeignKey("secretaria.id"), nullable=True)
    secretaria = db.relationship("Secretaria", foreign_keys=[secretaria_id])
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

    # Contratante (Representante Oficial — preenchido dinamicamente pela Secretaria)
    representante_nome = db.Column(db.String(150), default="")
    representante_cargo = db.Column(db.String(100), default="")
    representante_rg_cpf = db.Column(db.String(50), default="")
    representante_endereco = db.Column(db.String(200), default="")

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


class LocalVotacao(db.Model):
    __tablename__ = "local_votacao"

    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    zona_eleitoral = db.Column(db.String(20), nullable=False, default="018")
    secoes = db.Column(db.Text, nullable=False)  # Ex: "0012, 0013, 0014, 0015"
    bairro = db.Column(db.String(100), nullable=True)
    endereco = db.Column(db.String(200), nullable=True)
    cidade = db.Column(db.String(100), default="Valença do Piauí")
    uf = db.Column(db.String(2), default="PI")
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    observacoes = db.Column(db.Text, nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)

    def get_secoes_list(self):
        if not self.secoes:
            return []
        raw_items = re.split(r'[,;\s]+', str(self.secoes))
        return [item.strip() for item in raw_items if item.strip()]

    def get_secoes_normalized(self):
        result = set()
        for item in self.get_secoes_list():
            norm = normalizar_numero_eleitoral(item)
            if norm:
                result.add(norm)
        return result


class BackupHistorico(db.Model):
    __tablename__ = "backup_historico"

    id = db.Column(db.Integer, primary_key=True)
    nome_arquivo = db.Column(db.String(255), nullable=False)
    tipo = db.Column(db.String(30), default="MANUAL")  # MANUAL, PRE_RESTORE, RESTAURACAO
    status = db.Column(db.String(30), default="CONCLUIDO")
    tamanho_bytes = db.Column(db.BigInteger, default=0)
    sha256 = db.Column(db.String(64), nullable=True)
    total_tabelas = db.Column(db.Integer, default=0)
    total_registros = db.Column(db.Integer, default=0)
    total_arquivos = db.Column(db.Integer, default=0)
    origem_banco = db.Column(db.String(50), nullable=True)
    observacao = db.Column(db.Text, nullable=True)
    criado_por_id = db.Column(db.Integer, nullable=True)
    criado_por_nome = db.Column(db.String(100), nullable=True)
    ip_origem = db.Column(db.String(50), nullable=True)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)


def normalizar_numero_eleitoral(val):
    if not val:
        return ""
    digits = re.sub(r'\D', '', str(val))
    if not digits:
        return ""
    return digits.lstrip('0') or "0"


def gerar_proximo_numero_contrato(ano=None, secretaria_id=None):
    if not ano:
        ano = datetime.now().year
    try:
        q = ContratoGerado.query.filter_by(ano_exercicio=int(ano))
        sigla = ""
        if secretaria_id:
            q = q.filter_by(secretaria_id=int(secretaria_id))
            sec = db.session.get(Secretaria, int(secretaria_id))
            if sec and sec.sigla:
                sigla = f"-{sec.sigla.strip().upper()}"
        contratos = q.all()
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
        return f"{proximo:02d}/{ano}{sigla}"
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


def registrar_log(acao, alvo, nivel="INFO", secretaria_id=None):
    try:
        user_id = current_user.id if current_user.is_authenticated else None
        sec_id = secretaria_id
        if sec_id is None and current_user.is_authenticated:
            sec_id = getattr(current_user, "secretaria_id", None)

        ip = None
        ua = None
        rota = None
        if has_request_context():
            ip = request.remote_addr
            ua = str(request.user_agent)[:250]
            rota = request.path[:250]

        log = LogAuditoria(
            usuario_id=user_id,
            secretaria_id=sec_id,
            nivel=nivel,
            acao=str(acao)[:250],
            alvo=str(alvo)[:495],
            ip_origem=ip,
            user_agent=ua,
            rota_acessada=rota,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Erro log: {e}")


def registrar_violacao_acesso(alvo):
    """Registra tentativa de acesso fora do escopo da secretaria/permissão."""
    registrar_log("VIOLACAO_ESCOPO_BLOQUEADA", alvo, nivel="SECURITY")


def obter_dados_representante_secretaria(sec_obj):
    """Retorna os dados do representante oficial da Secretaria para contratos/documentos."""
    if not sec_obj:
        return {
            "nome": "",
            "cargo": "",
            "cpf": "",
            "endereco": "",
        }
    return {
        "nome": (sec_obj.secretario_nome or "").strip(),
        "cargo": (sec_obj.secretario_cargo or f"Secretário(a) de {sec_obj.nome}").strip(),
        "cpf": (sec_obj.secretario_cpf or "").strip(),
        "endereco": (sec_obj.endereco or "").strip(),
    }


@app.context_processor
def inject_global_data():
    data = {
        "pending_count": 0,
        "notifications": [],
        "aviso_sistema": None,
        "mostrar_termo": False,
        "csrf_token": security.get_csrf_token,
        "has_perm": lambda perm: security.has_permission(current_user, perm),
        "user_role": security.normalize_role(current_user) if current_user.is_authenticated else "anonymous",
        "user_role_label": security.get_role_label(current_user) if current_user.is_authenticated else "",
        "is_global_scope": security.has_global_scope(current_user) if current_user.is_authenticated else False,
        "ROLE_METADATA": security.ROLE_METADATA,
    }

    if current_user.is_authenticated:
        if security.has_permission(current_user, "validate_cadastros"):
            try:
                q_pend = security.scope_query(
                    Funcionario.query.filter_by(validado=False), Funcionario, current_user
                )
                data["pending_count"] = q_pend.count()
            except Exception:
                pass
        try:
            q_logs = LogAuditoria.query
            if not security.has_global_scope(current_user):
                q_logs = q_logs.filter(
                    (LogAuditoria.nivel.is_(None)) | (LogAuditoria.nivel != "SECURITY")
                )
                if current_user.secretaria_id:
                    q_logs = q_logs.filter(LogAuditoria.secretaria_id == current_user.secretaria_id)
                else:
                    q_logs = q_logs.filter(LogAuditoria.usuario_id == current_user.id)
            data["notifications"] = (
                q_logs.order_by(LogAuditoria.data_hora.desc()).limit(5).all()
            )
        except Exception:
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
            if attr.key not in ['token_validacao', 'cpf_limpo']: 
                dados_antigos[attr.key] = str(val_antigo) if val_antigo is not None else ""
                dados_novos[attr.key] = str(val_novo) if val_novo is not None else ""

    if dados_antigos or dados_novos:
        try:
            usuario_id = current_user.id if current_user.is_authenticated else None
        except Exception:
            usuario_id = None

        alvo_texto = f"Ficha {target.nome} atualizada"

        connection.execute(
            LogAuditoria.__table__.insert(),
            {
                "usuario_id": usuario_id,
                "secretaria_id": target.secretaria_id,
                "nivel": "INFO",
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
        return redirect(url_for(security.get_default_home_endpoint(current_user)))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip_key = f"login:{request.remote_addr}"
        limited, retry_after = security.login_rate_limiter.is_limited(ip_key, max_attempts=15, window_seconds=300)
        if limited:
            flash(f"Muitas tentativas de acesso. Aguarde {retry_after} segundos para tentar novamente.", "error")
            return render_template("login.html"), 429

        username = (request.form.get("user") or "").strip()
        password = request.form.get("pass") or ""
        user = User.query.filter_by(username=username).first()

        if user:
            # Verifica conta desativada
            if user.ativo is False:
                registrar_log("LOGIN_CONTA_INATIVA", f"Tentativa em conta desativada: {username}", nivel="SECURITY", secretaria_id=user.secretaria_id)
                flash("Esta conta está desativada. Procure o administrador.", "error")
                return render_template("login.html"), 403

            # Verifica bloqueio temporário por força bruta
            if user.bloqueado_ate and user.bloqueado_ate > datetime.utcnow():
                mins = max(1, int((user.bloqueado_ate - datetime.utcnow()).total_seconds() / 60) + 1)
                flash(f"Conta temporariamente bloqueada por excesso de tentativas. Aguarde {mins} minuto(s) ou solicite desbloqueio.", "error")
                return render_template("login.html"), 423

        if user and user.check_password(password):
            security.login_rate_limiter.reset(ip_key)
            user.tentativas_falhas = 0
            user.bloqueado_ate = None
            user.ultimo_login_em = datetime.utcnow()
            user.ultimo_login_ip = request.remote_addr
            db.session.commit()

            login_user(user)
            registrar_log("LOGIN", f"Acesso realizado ({user.role_label})", nivel="INFO", secretaria_id=user.secretaria_id)

            if not user.termo_aceito:
                flash("abrir_modal", "aviso_lgpd")

            return redirect(url_for(security.get_default_home_endpoint(user)))
        else:
            security.login_rate_limiter.register_failure(ip_key)
            if user:
                user.tentativas_falhas = (user.tentativas_falhas or 0) + 1
                if user.tentativas_falhas >= 5:
                    user.bloqueado_ate = datetime.utcnow() + timedelta(minutes=15)
                    db.session.commit()
                    registrar_log("BLOQUEIO_FORCA_BRUTA", f"Conta {username} bloqueada por 15 min após 5 falhas", nivel="SECURITY", secretaria_id=user.secretaria_id)
                    flash("Conta bloqueada por 15 minutos após 5 tentativas inválidas.", "error")
                    return render_template("login.html"), 423
                db.session.commit()
            flash("Usuário ou senha inválidos.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    reason = request.args.get("reason")
    logout_user()
    if reason == "inactivity":
        flash("Sua sessão foi encerrada após 15 minutos de inatividade por motivos de segurança.", "warning")
    return redirect(url_for("login"))


@app.route("/api/ping_session", methods=["POST", "GET"])
def ping_session():
    if current_user and current_user.is_authenticated:
        session.permanent = True
        session.modified = True
        return jsonify({"success": True, "message": "Sessão renovada com sucesso."})
    return jsonify({"success": False, "message": "Usuário não autenticado."}), 401


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
    if not security.has_permission(current_user, "view_rh"):
        return "Acesso negado", 403
    f = db.session.get(Funcionario, id)
    if not f or not security.can_access_record(current_user, f):
        registrar_violacao_acesso(f"HistoricoLotacao funcionario_id={id}")
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
@security.require_permission("validate_cadastros")
def validar_cadastros():
    secretaria_id = request.args.get("secretaria_id")
    busca = request.args.get("busca")
    page = request.args.get("page", 1, type=int)

    query = security.scope_query(Funcionario.query, Funcionario, current_user)
    if secretaria_id and security.has_global_scope(current_user):
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
    secretarias = (
        Secretaria.query.order_by(Secretaria.nome).all()
        if security.has_global_scope(current_user)
        else Secretaria.query.filter_by(id=current_user.secretaria_id).all()
    )
    return render_template(
        "validar_cadastros.html",
        funcionarios=funcionarios,
        secretarias=secretarias,
        pagination=pagination,
    )


@app.route("/aprovar_cadastro/<int:id>", methods=["GET", "POST"])
@login_required
@security.require_permission("validate_cadastros")
def aprovar_cadastro(id):
    func_obj = db.session.get(Funcionario, id)
    if func_obj:
        if not security.can_access_record(current_user, func_obj):
            registrar_violacao_acesso(f"Aprovar cadastro funcionario_id={id}")
            flash("Acesso negado: servidor pertence a outra secretaria.", "error")
            return redirect(url_for("validar_cadastros"))
        func_obj.validado = True
        db.session.commit()
        registrar_log("VALIDOU CADASTRO", func_obj.nome, secretaria_id=func_obj.secretaria_id)
        flash(f"Cadastro de {func_obj.nome} validado com sucesso!", "success")
    return redirect(url_for("validar_cadastros"))


@app.route("/revogar_validacao/<int:id>", methods=["GET", "POST"])
@login_required
@security.require_permission("validate_cadastros")
def revogar_validacao(id):
    func_obj = db.session.get(Funcionario, id)
    if func_obj:
        if not security.can_access_record(current_user, func_obj):
            registrar_violacao_acesso(f"Revogar validacao funcionario_id={id}")
            flash("Acesso negado: servidor pertence a outra secretaria.", "error")
            return redirect(url_for("validar_cadastros"))
        func_obj.validado = False
        db.session.commit()
        registrar_log("REVOGOU VALIDACAO", func_obj.nome, secretaria_id=func_obj.secretaria_id)
        flash(f"Validação de {func_obj.nome} revogada com sucesso!", "success")
    return redirect(url_for("validar_cadastros"))


@app.route("/exportar_pendentes")
@login_required
@security.require_permission("validate_cadastros")
def exportar_pendentes():
    secretaria_id = request.args.get("secretaria_id")
    busca = request.args.get("busca")

    query = security.scope_query(
        Funcionario.query.filter_by(validado=False), Funcionario, current_user
    )

    if secretaria_id and security.has_global_scope(current_user):
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
                f.secretaria.nome if f.secretaria else "",
                f.funcao.nome if f.funcao else "",
                f.tipo_vinculo,
                f.data_criacao.strftime("%d/%m/%Y") if f.data_criacao else "",
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
@security.require_permission("view_rescisoes")
def pagina_recisoes():
    ativos_q = security.scope_query(
        Funcionario.query.filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None))),
        Funcionario,
        current_user,
    )
    ativos = ativos_q.order_by(Funcionario.nome).all()

    locais_q = security.scope_query(LocalTrabalho.query, LocalTrabalho, current_user)
    locais = locais_q.order_by(LocalTrabalho.nome).all()

    historico_q = security.scope_query(RescisaoHistorico.query, RescisaoHistorico, current_user)
    historico = historico_q.order_by(RescisaoHistorico.data_geracao.desc()).all()
    return render_template("recisao_painel.html", ativos=ativos, historico=historico, locais=locais)


@app.route("/admin", methods=["GET", "POST"])
@login_required
@security.require_permission("view_admin_panel")
def admin_dashboard():
    is_global = security.has_global_scope(current_user)

    if request.method == "POST":
        # CRIAR SECRETARIA (Apenas Super Admin)
        if "create_secretaria" in request.form:
            if not security.has_permission(current_user, "manage_secretarias"):
                flash("Acesso negado: apenas Master TI pode criar secretarias.", "error")
                return redirect(url_for("admin_dashboard", tab="config"))
            nome_sec = (request.form.get("nome_secretaria") or "").strip().upper()
            sigla_sec = (request.form.get("sigla_secretaria") or "").strip().upper() or None
            secretario_nome = (request.form.get("secretario_nome") or "").strip().upper() or None
            if nome_sec and not Secretaria.query.filter_by(nome=nome_sec).first():
                nova_sec = Secretaria(
                    nome=nome_sec,
                    sigla=sigla_sec,
                    secretario_nome=secretario_nome,
                    secretario_cargo=f"Secretário(a) de {nome_sec}",
                    ativa=True,
                )
                db.session.add(nova_sec)
                db.session.commit()
                registrar_log("CRIOU SECRETARIA", nome_sec, secretaria_id=nova_sec.id)
                flash(f"Secretaria '{nome_sec}' criada com sucesso!", "success")
            else:
                flash("Secretaria já existe ou nome inválido.", "error")
            return redirect(url_for("admin_dashboard", tab="config"))

        # CRIAR FUNCAO
        if "create_funcao" in request.form:
            if not security.has_permission(current_user, "manage_funcoes"):
                flash("Acesso negado.", "error")
                return redirect(url_for("admin_dashboard", tab="config"))
            nome_funcao = (request.form.get("nome_funcao") or "").strip().upper()
            if nome_funcao and not Funcao.query.filter_by(nome=nome_funcao).first():
                db.session.add(Funcao(nome=nome_funcao))
                db.session.commit()
                registrar_log("CRIOU FUNCAO", nome_funcao)
                flash("Função criada!", "success")
            return redirect(url_for("admin_dashboard", tab="config"))

        if "create_local" in request.form:
            if not security.has_permission(current_user, "manage_locais"):
                flash("Acesso negado.", "error")
                return redirect(url_for("admin_dashboard", tab="config"))
            nome = (request.form.get("nome_local") or "").strip()
            lat = request.form.get("latitude")
            lng = request.form.get("longitude")
            raio = request.form.get("raio_permitido")
            tipo_unidade = (request.form.get("tipo_unidade") or "UNIDADE").strip().upper()

            if is_global:
                sec_local_id = request.form.get("secretaria_id", type=int) or current_user.secretaria_id
            else:
                sec_local_id = current_user.secretaria_id

            if nome:
                latitude = float(lat) if lat and lat.strip() else None
                longitude = float(lng) if lng and lng.strip() else None
                raio_permitido = int(raio) if raio and raio.strip() else 50

                novo_local = LocalTrabalho(
                    nome=nome,
                    secretaria_id=sec_local_id,
                    tipo_unidade=tipo_unidade,
                    latitude=latitude,
                    longitude=longitude,
                    raio_permitido=raio_permitido,
                    ativa=True,
                )
                db.session.add(novo_local)
                db.session.commit()
                registrar_log("CRIOU LOCAL", nome, secretaria_id=sec_local_id)
                flash(f'Local "{nome}" cadastrado com sucesso!', "success")
            return redirect(url_for("admin_dashboard", tab="config"))

        # CRIAR PADRINHO
        if "create_padrinho" in request.form:
            if not security.has_permission(current_user, "manage_padrinhos"):
                flash("Acesso negado: apenas Prefeito/Estratégia/Master podem gerenciar padrinhos.", "error")
                return redirect(url_for("admin_dashboard", tab="config"))
            nome_padrinho = (request.form.get("nome_padrinho") or "").strip().upper()
            if nome_padrinho and not Padrinho.query.filter_by(nome=nome_padrinho).first():
                db.session.add(Padrinho(nome=nome_padrinho))
                db.session.commit()
                registrar_log("CRIOU PADRINHO", nome_padrinho)
                flash("Padrinho/Indicador criado!", "success")
            return redirect(url_for("admin_dashboard", tab="config"))

        # CRIAR USUÁRIO (Apenas Super Admin)
        elif "create_user" in request.form:
            if not security.has_permission(current_user, "manage_users"):
                flash("Acesso negado: apenas Master TI pode criar usuários.", "error")
                return redirect(url_for("admin_dashboard", tab="config"))
            username = (request.form.get("username") or "").strip()
            nome_completo = (request.form.get("nome_completo") or "").strip().upper() or None
            email_user = (request.form.get("email") or "").strip() or None
            sec_id_form = request.form.get("secretaria_id", type=int)
            local_id_form = request.form.get("local_trabalho_id", type=int)
            role_form = (request.form.get("role") or "rh_secretaria").strip()
            senha_form = request.form.get("password") or ""

            if role_form not in security.ROLE_METADATA and role_form not in security.LEGACY_ROLE_MAP:
                flash("Nível de acesso inválido.", "error")
                return redirect(url_for("admin_dashboard", tab="config"))

            norm_role = security.LEGACY_ROLE_MAP.get(role_form, role_form)
            role_scope = security.ROLE_METADATA[norm_role]["scope"]

            if role_scope != "global" and not sec_id_form:
                flash("Erro: Selecione uma Secretaria para este nível de acesso!", "error")
                return redirect(url_for("admin_dashboard", tab="config"))
            if norm_role == "chefe_unidade" and not local_id_form:
                flash("Erro: Selecione o Local de Trabalho para o Chefe de Unidade!", "error")
                return redirect(url_for("admin_dashboard", tab="config"))

            ok_pwd, msg_pwd = security.validate_password_strength(senha_form)
            if not ok_pwd:
                flash(f"Senha fraca: {msg_pwd}", "error")
                return redirect(url_for("admin_dashboard", tab="config"))

            if not User.query.filter_by(username=username).first():
                is_admin_bool = norm_role == "super_admin"
                u = User(
                    username=username,
                    nome_completo=nome_completo,
                    email=email_user,
                    secretaria_id=sec_id_form,
                    local_trabalho_id=local_id_form if norm_role == "chefe_unidade" else None,
                    role=norm_role,
                    is_admin=is_admin_bool,
                    ativo=True,
                )
                u.set_password(senha_form)
                db.session.add(u)
                db.session.commit()
                registrar_log("CRIOU USUÁRIO", f"{username} [{norm_role}] (Sec ID: {sec_id_form})", secretaria_id=sec_id_form)
                flash(f"Usuário {username} ({security.get_role_label(norm_role)}) criado com sucesso!", "success")
            else:
                flash("Usuário já existe!", "error")
            return redirect(url_for("admin_dashboard", tab="config"))

    # --- LÓGICA DE FILTRAGEM COM ISOLAMENTO MULTI-SECRETARIAS ---
    filtro_secretaria = request.args.get("secretaria_id") if is_global else str(current_user.secretaria_id or "")
    filtro_vinculo = request.args.get("tipo_vinculo")
    filtro_indicacao = request.args.get("padrinho_id") if security.has_permission(current_user, "view_padrinhos") else None
    filtro_funcao = request.args.get("funcao_id")
    filtro_local = request.args.get("local_trabalho_id")
    busca_termo = request.args.get("busca_termo")

    base_ativos = security.scope_query(
        Funcionario.query.filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None))),
        Funcionario,
        current_user,
    )
    query = base_ativos

    if filtro_secretaria and is_global:
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
    custo_folha_total = round(sum((f.remuneracao_valor or 0.0) for f in funcionarios_filtrados), 2)

    lista_padrinhos = (
        Padrinho.query.order_by(Padrinho.nome).all()
        if security.has_permission(current_user, "view_padrinhos")
        else []
    )

    stats_sec_q = (
        db.session.query(Secretaria.nome, func.count(Funcionario.id))
        .join(Funcionario)
        .filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None)))
    )
    if not is_global:
        stats_sec_q = stats_sec_q.filter(Funcionario.secretaria_id == current_user.secretaria_id)
    stats_secretaria = {s[0]: s[1] for s in stats_sec_q.group_by(Secretaria.nome).all()}

    stats_vinculo_q = (
        db.session.query(Funcionario.tipo_vinculo, func.count(Funcionario.id))
        .filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None)))
    )
    if not is_global:
        stats_vinculo_q = stats_vinculo_q.filter(Funcionario.secretaria_id == current_user.secretaria_id)
    stats_vinculo = {
        (v[0] if v[0] else "Não Informado"): v[1]
        for v in stats_vinculo_q.group_by(Funcionario.tipo_vinculo).all()
    }

    count_validados = base_ativos.filter(Funcionario.validado == True).count()
    count_pendentes = base_ativos.filter(Funcionario.validado == False).count()
    stats_validacao = {"Aptos": count_validados, "Pendentes": count_pendentes}

    locais_stats_query = (
        db.session.query(LocalTrabalho.nome, func.count(Funcionario.id))
        .join(Funcionario, Funcionario.local_trabalho_id == LocalTrabalho.id)
        .filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None)))
    )
    if not is_global:
        locais_stats_query = locais_stats_query.filter(
            Funcionario.secretaria_id == current_user.secretaria_id
        )
    elif filtro_secretaria:
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
    logs_q = LogAuditoria.query
    if not is_global:
        logs_q = logs_q.filter(
            LogAuditoria.secretaria_id == current_user.secretaria_id,
            LogAuditoria.acao != "ALERTA_ACUMULO_CPF",
        )
    logs_pagination = logs_q.order_by(LogAuditoria.data_hora.desc()).paginate(
        page=page_auditoria, per_page=per_page_auditoria, error_out=False
    )
    logs = logs_pagination.items

    secretarias = (
        Secretaria.query.order_by(Secretaria.nome).all()
        if is_global
        else Secretaria.query.filter_by(id=current_user.secretaria_id).all()
    )
    users = (
        User.query.order_by(User.username).all()
        if security.has_permission(current_user, "manage_users")
        else []
    )
    funcoes = Funcao.query.order_by(Funcao.nome).all()
    locais_trabalho = security.scope_query(
        LocalTrabalho.query, LocalTrabalho, current_user
    ).order_by(LocalTrabalho.nome).all()

    try:
        atest_q = security.scope_query(
            JustificativaFalta.query.filter_by(status='PENDENTE'),
            JustificativaFalta,
            current_user,
        )
        atestados_pendentes_count = atest_q.count()
    except Exception:
        atestados_pendentes_count = 0

    return render_template(
        "admin.html",
        secretarias=secretarias,
        funcoes=funcoes,
        locais_trabalho=locais_trabalho,
        padrinhos=lista_padrinhos,
        users=users,
        funcionarios=funcionarios_filtrados,
        total_geral=total_filtrado,
        custo_folha_total=custo_folha_total,
        stats_secretaria=stats_secretaria,
        stats_vinculo=stats_vinculo,
        stats_validacao=stats_validacao,
        locais_stats=locais_stats,
        logs=logs,
        atestados_pendentes_count=atestados_pendentes_count,
        filtros={
            "sec": filtro_secretaria if is_global else "",
            "vinculo": filtro_vinculo,
            "indicacao": filtro_indicacao,
            "busca": busca_termo,
            "funcao": filtro_funcao,
            "local": filtro_local,
        },
        role=current_user.normalized_role,
        is_admin=security.is_super_admin(current_user),
    )


@app.route("/processar_recisao", methods=["POST"])
@login_required
@security.require_permission("manage_rescisoes")
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

    if not security.can_access_record(current_user, funcionario):
        registrar_violacao_acesso(f"Rescisao funcionario_id={id_func}")
        flash("Acesso negado: servidor pertence a outra secretaria.", "error")
        return redirect(url_for("pagina_recisoes"))

    if not dt_ini:
        dt_ini = funcionario.dt_inicio
    if not dt_sai:
        dt_sai = date.today()

    try:
        nova_rescisao = RescisaoHistorico(
            secretaria_id=funcionario.secretaria_id,
            nome=funcionario.nome,
            cpf=funcionario.cpf,
            rg=funcionario.rg,
            endereco=funcionario.endereco,
            funcao=funcionario.funcao.nome if funcionario.funcao else "N/A",
            num_contrato=funcionario.num_vinculo,
            data_inicio=dt_ini,
            data_saida=dt_sai,
        )
        db.session.add(nova_rescisao)

        dados_doc = {
            "nome": funcionario.nome,
            "funcao": funcionario.funcao.nome if funcionario.funcao else "N/A",
            "data_inicio": dt_ini,
            "data_saida": dt_sai,
            "cpf": funcionario.cpf,
            "rg": funcionario.rg,
            "endereco": funcionario.endereco,
            "num_contrato": funcionario.num_vinculo,
            "secretaria_nome": funcionario.secretaria.nome if funcionario.secretaria else "",
        }

        funcionario.ativo = False
        funcionario.dt_termino = dt_sai
        if dt_ini:
            funcionario.dt_inicio = dt_ini

        nome_servidor = funcionario.nome
        sec_id_func = funcionario.secretaria_id
        db.session.commit()

        registrar_log("GEROU RESCISAO", nome_servidor, secretaria_id=sec_id_func)

        fuso_br = pytz.timezone('America/Sao_Paulo')
        agora_br = datetime.now(fuso_br).replace(tzinfo=None)

        return render_template(
            "recisao_documento.html", f=dados_doc, data_atual=agora_br
        )

    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao processar baixa: {str(e)}", "error")
        return redirect(url_for("pagina_recisoes"))


@app.route("/api/servidores_por_local")
@login_required
@security.require_permission("view_rh", api=True)
def api_servidores_por_local():
    local_id = request.args.get("local_id")
    if not local_id:
        return jsonify([])

    servidores_q = security.scope_query(
        Funcionario.query.filter(
            Funcionario.local_trabalho_id == local_id,
            (Funcionario.ativo == True) | (Funcionario.ativo.is_(None)),
        ),
        Funcionario,
        current_user,
    )
    servidores = servidores_q.order_by(Funcionario.nome).all()

    resultado = []
    for s in servidores:
        dt_ini_str = s.dt_inicio.strftime("%d/%m/%Y") if s.dt_inicio else "N/D"
        resultado.append({
            "id": s.id,
            "nome": s.nome,
            "cpf": s.cpf or "N/D",
            "funcao": s.funcao.nome if s.funcao else "N/A",
            "dt_inicio": dt_ini_str,
            "dt_inicio_iso": s.dt_inicio.strftime("%Y-%m-%d") if s.dt_inicio else ""
        })
    return jsonify(resultado)


@app.route("/processar_recisao_massa", methods=["POST"])
@login_required
@security.require_permission("manage_rescisoes")
def processar_recisao_massa():
    local_id = request.form.get("local_id")
    data_saida_str = request.form.get("data_saida")
    func_ids = request.form.getlist("func_ids")

    dt_sai = parse_date(data_saida_str) or date.today()

    if not func_ids:
        flash("Nenhum servidor foi selecionado para rescisão em massa.", "error")
        return redirect(url_for("pagina_recisoes"))

    local_obj = db.session.get(LocalTrabalho, local_id) if local_id else None
    if local_obj and not security.can_access_record(current_user, local_obj):
        registrar_violacao_acesso(f"Rescisao massa local_id={local_id}")
        flash("Acesso negado: local pertence a outra secretaria.", "error")
        return redirect(url_for("pagina_recisoes"))

    local_nome = local_obj.nome if local_obj else "Local Desconhecido"

    count = 0
    try:
        for fid in func_ids:
            func_obj = db.session.get(Funcionario, int(fid))
            if (
                func_obj
                and security.can_access_record(current_user, func_obj)
                and (func_obj.ativo is True or func_obj.ativo is None)
            ):
                dt_ini = func_obj.dt_inicio or date.today()
                nova_rescisao = RescisaoHistorico(
                    secretaria_id=func_obj.secretaria_id,
                    nome=func_obj.nome,
                    cpf=func_obj.cpf,
                    rg=func_obj.rg,
                    endereco=func_obj.endereco,
                    funcao=func_obj.funcao.nome if func_obj.funcao else "N/A",
                    num_contrato=func_obj.num_vinculo,
                    data_inicio=dt_ini,
                    data_saida=dt_sai,
                )
                db.session.add(nova_rescisao)

                func_obj.ativo = False
                func_obj.dt_termino = dt_sai
                count += 1

        db.session.commit()
        registrar_log("RESCISAO EM MASSA", f"{count} servidores inativados em {local_nome}")
        flash(f"Rescisão em massa concluída com sucesso! {count} servidores foram inativados.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao processar rescisão em massa: {str(e)}", "error")

    return redirect(url_for("pagina_recisoes"))


@app.route("/api/buscar_servidor_inativo_cpf")
@login_required
@security.require_permission("write_rh", api=True)
def buscar_servidor_inativo_cpf():
    cpf_raw = request.args.get("cpf", "").strip()
    cpf_clean = re.sub(r"\D", "", cpf_raw)
    if not cpf_clean or len(cpf_clean) != 11:
        return jsonify({"encontrado": False})

    # Busca indexada e isolada por secretaria!
    q = security.scope_query(
        Funcionario.query.filter(
            Funcionario.ativo == False,
            (Funcionario.cpf_limpo == cpf_clean) | (Funcionario.cpf == cpf_raw),
        ),
        Funcionario,
        current_user,
    )
    func_inativo = q.order_by(Funcionario.id.desc()).first()

    if not func_inativo:
        return jsonify({"encontrado": False})

    return jsonify({
        "encontrado": True,
        "funcionario": {
            "id": func_inativo.id,
            "nome": func_inativo.nome or "",
            "cpf": func_inativo.cpf or "",
            "rg": func_inativo.rg or "",
            "orgao_emissor_rg": func_inativo.orgao_emissor_rg or "",
            "data_expedicao_rg": func_inativo.data_expedicao_rg.strftime("%Y-%m-%d") if func_inativo.data_expedicao_rg else "",
            "data_nasc": func_inativo.data_nasc.strftime("%Y-%m-%d") if func_inativo.data_nasc else "",
            "genero": func_inativo.genero or "",
            "estado_civil": func_inativo.estado_civil or "",
            "nacionalidade": func_inativo.nacionalidade or "BRASILEIRA",
            "mae": func_inativo.mae or "",
            "pai": func_inativo.pai or "",
            "escolaridade": func_inativo.escolaridade or "",
            "especialidade": func_inativo.especialidade or "",
            "telefone": func_inativo.telefone or "",
            "email": func_inativo.email or "",
            "cep": func_inativo.cep or "",
            "bairro": func_inativo.bairro or "",
            "cidade": func_inativo.cidade or "VALENÇA DO PIAUÍ",
            "uf": func_inativo.uf or "PI",
            "endereco": func_inativo.endereco or "",
            "pis": func_inativo.pis or "",
            "titulo_eleitor": func_inativo.titulo_eleitor or "",
            "zona_eleitoral": func_inativo.zona_eleitoral or "",
            "secao_eleitoral": func_inativo.secao_eleitoral or "",
            "is_pcd": "sim" if func_inativo.is_pcd else "nao",
            "tipo_deficiencia": func_inativo.tipo_deficiencia or "",
            "qtd_dependentes": func_inativo.qtd_dependentes or 0,
            "ctps": func_inativo.ctps or "",
            "cnh": func_inativo.cnh or "",
            "banco": func_inativo.banco or "",
            "agencia": func_inativo.agencia or "",
            "conta": func_inativo.conta or "",
            "tipo_conta": func_inativo.tipo_conta or "",
            "contato_emergencia_nome": func_inativo.contato_emergencia_nome or "",
            "contato_emergencia_tel": func_inativo.contato_emergencia_tel or "",
            "tipo_sanguineo": func_inativo.tipo_sanguineo or "",
            "funcao_id": func_inativo.funcao_id or "",
            "local_trabalho_id": func_inativo.local_trabalho_id or "",
            "tipo_vinculo": func_inativo.tipo_vinculo or "",
            "remuneracao": func_inativo.remuneracao or "",
            "jornada_trabalho": func_inativo.jornada_trabalho or "",
        }
    })


@app.route("/api/alterar_minha_senha", methods=["POST"])
@login_required
def api_alterar_minha_senha():
    try:
        data = request.get_json(silent=True) or request.form
        nova_senha = (data.get("nova_senha") or "").strip()
        ok_pwd, msg_pwd = security.validate_password_strength(nova_senha)
        if not ok_pwd:
            return jsonify({"success": False, "message": msg_pwd}), 400

        current_user.set_password(nova_senha)
        current_user.pergunta_troca_senha_exibida = True
        current_user.precisa_trocar_senha = False
        db.session.commit()
        registrar_log("REDEFINIU SENHA PROPRIA", current_user.username)
        return jsonify({"success": True, "message": "Senha alterada com sucesso!"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/dispensar_troca_senha", methods=["POST"])
@login_required
def api_dispensar_troca_senha():
    try:
        current_user.pergunta_troca_senha_exibida = True
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/varredura_duplicados")
@login_required
@security.require_permission("scan_duplicados", api=True)
def api_varredura_duplicados():
    funcionarios = security.scope_query(Funcionario.query, Funcionario, current_user).all()
    grupos_cpf = {}

    for f in funcionarios:
        cpf_clean = f.cpf_limpo or (re.sub(r"\D", "", f.cpf) if f.cpf else "")
        if len(cpf_clean) != 11:
            continue
        grupos_cpf.setdefault(cpf_clean, []).append(f)

    grupos_duplicados = []
    total_duplicados = 0

    for cpf_clean, lista in grupos_cpf.items():
        if len(lista) >= 2:
            lista_ordenada = sorted(lista, key=lambda x: (not x.validado, x.id))
            original = lista_ordenada[0]
            duplicados = lista_ordenada[1:]
            total_duplicados += len(duplicados)

            cpf_fmt = f"{cpf_clean[:3]}.{cpf_clean[3:6]}.{cpf_clean[6:9]}-{cpf_clean[9:]}"
            orig_dt = original.data_criacao.strftime("%d/%m/%Y") if original.data_criacao else "N/D"

            duplicados_data = []
            for dup in duplicados:
                dup_dt = dup.data_criacao.strftime("%d/%m/%Y") if dup.data_criacao else "N/D"
                duplicados_data.append({
                    "id": dup.id,
                    "nome": dup.nome,
                    "cpf": dup.cpf or cpf_fmt,
                    "data_criacao": dup_dt,
                    "num_vinculo": dup.num_vinculo or "N/D",
                    "tipo_vinculo": dup.tipo_vinculo or "N/D",
                    "secretaria": dup.lotacao or (dup.secretaria.nome if dup.secretaria else "N/D"),
                    "local": dup.local_trabalho.nome if dup.local_trabalho else "N/D",
                    "funcao": dup.funcao.nome if dup.funcao else "N/D",
                    "validado": dup.validado,
                    "ativo": dup.ativo
                })

            grupos_duplicados.append({
                "cpf_clean": cpf_clean,
                "cpf_formatado": cpf_fmt,
                "total_no_grupo": len(lista),
                "original": {
                    "id": original.id,
                    "nome": original.nome,
                    "cpf": original.cpf or cpf_fmt,
                    "data_criacao": orig_dt,
                    "num_vinculo": original.num_vinculo or "N/D",
                    "tipo_vinculo": original.tipo_vinculo or "N/D",
                    "secretaria": original.lotacao or (original.secretaria.nome if original.secretaria else "N/D"),
                    "local": original.local_trabalho.nome if original.local_trabalho else "N/D",
                    "funcao": original.funcao.nome if original.funcao else "N/D",
                    "validado": original.validado,
                    "ativo": original.ativo
                },
                "duplicados": duplicados_data
            })

    return jsonify({
        "success": True,
        "total_grupos": len(grupos_duplicados),
        "total_duplicados": total_duplicados,
        "grupos": grupos_duplicados
    })


@app.route("/api/excluir_duplicado/<int:func_id>", methods=["POST"])
@login_required
@security.require_permission("delete_permanently", api=True)
def api_excluir_duplicado(func_id):
    ficha = db.session.get(Funcionario, func_id)
    if not ficha:
        return jsonify({"success": False, "message": "Registro não encontrado."}), 404

    try:
        nome_servidor = ficha.nome
        cpf_servidor = ficha.cpf or "N/D"
        sec_id = ficha.secretaria_id

        HistoricoLotacao.query.filter_by(funcionario_id=func_id).delete()
        RegistroPonto.query.filter_by(funcionario_id=func_id).delete()

        db.session.delete(ficha)
        db.session.commit()

        registrar_log("EXCLUIU CADASTRO DUPLICADO", f"{nome_servidor} (CPF: {cpf_servidor}, ID #{func_id})", secretaria_id=sec_id)
        return jsonify({
            "success": True,
            "message": f"Cadastro duplicado #{func_id} de {nome_servidor} foi excluído permanentemente. O registro original foi mantido seguro."
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Erro ao excluir duplicado: {str(e)}"}), 500


@app.route("/admin/editar_secretaria", methods=["POST"])
@login_required
@security.require_permission("manage_secretarias")
def editar_secretaria():
    sec_id = request.form.get("secretaria_id", type=int)
    sec = db.session.get(Secretaria, sec_id) if sec_id else None
    if not sec:
        flash("Secretaria não encontrada.", "error")
        return redirect(url_for("admin_dashboard", tab="config"))

    nome = (request.form.get("nome") or sec.nome).strip().upper()
    if nome and nome != sec.nome and Secretaria.query.filter(Secretaria.nome == nome, Secretaria.id != sec.id).first():
        flash("Já existe outra secretaria com este nome.", "error")
        return redirect(url_for("admin_dashboard", tab="config"))

    sec.nome = nome
    sec.sigla = (request.form.get("sigla") or "").strip().upper() or None
    sec.cnpj = (request.form.get("cnpj") or "").strip() or None
    sec.endereco = (request.form.get("endereco") or "").strip() or None
    sec.telefone = (request.form.get("telefone") or "").strip() or None
    sec.email = (request.form.get("email") or "").strip() or None
    sec.secretario_nome = (request.form.get("secretario_nome") or "").strip().upper() or None
    sec.secretario_cargo = (request.form.get("secretario_cargo") or "").strip() or None
    sec.secretario_cpf = (request.form.get("secretario_cpf") or "").strip() or None
    sec.secretario_portaria = (request.form.get("secretario_portaria") or "").strip() or None
    sec.teto_comissionados = request.form.get("teto_comissionados", type=int) or 0
    sec.teto_folha_mensal = security.parse_remuneracao_float(request.form.get("teto_folha_mensal"))
    sec.ativa = request.form.get("ativa", "1") in ("1", "true", "on", "sim")

    db.session.commit()
    registrar_log("EDITOU SECRETARIA", f"{sec.nome} ({sec.sigla or '-'})", secretaria_id=sec.id)
    flash(f"Perfil institucional de '{sec.nome}' atualizado com sucesso!", "success")
    return redirect(url_for("admin_dashboard", tab="config"))


@app.route("/admin/editar_local", methods=["POST"])
@login_required
@security.require_permission("manage_locais")
def editar_local():
    id_local = request.form.get("id_local")
    local = db.session.get(LocalTrabalho, id_local)

    if local:
        if not security.can_access_record(current_user, local):
            registrar_violacao_acesso(f"Editar local_id={id_local}")
            flash("Acesso negado: local pertence a outra secretaria.", "error")
            return redirect(url_for("admin_dashboard", tab="config"))

        local.nome = request.form.get("nome_local")
        lat = request.form.get("latitude")
        lng = request.form.get("longitude")
        raio = request.form.get("raio_permitido")
        tipo_unidade = (request.form.get("tipo_unidade") or local.tipo_unidade or "UNIDADE").strip().upper()

        if security.has_global_scope(current_user) and request.form.get("secretaria_id"):
            local.secretaria_id = request.form.get("secretaria_id", type=int)

        local.tipo_unidade = tipo_unidade
        local.latitude = float(lat) if lat and lat.strip() else None
        local.longitude = float(lng) if lng and lng.strip() else None
        local.raio_permitido = int(raio) if raio and raio.strip() else 50

        db.session.commit()
        registrar_log("EDITOU LOCAL", local.nome, secretaria_id=local.secretaria_id)
        flash("Configurações do local atualizadas!", "success")

    return redirect(url_for("admin_dashboard", tab="config"))


@app.route("/admin/reconhecimento_facial")
@login_required
@security.require_permission("manage_biometria")
def reconhecimento_facial():
    funcionarios = security.scope_query(
        Funcionario.query, Funcionario, current_user
    ).order_by(Funcionario.nome).all()
    return render_template(
        "reconhecimento_facial.html", lista_funcionarios=funcionarios
    )


@app.route("/admin/cargos_total")
@login_required
@security.require_permission("view_admin_panel")
def cargos_total():
    funcionarios = security.scope_query(
        Funcionario.query.filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None))),
        Funcionario,
        current_user,
    ).all()

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

    stats_cargos = dict(sorted(stats_cargos.items()))

    return render_template("cargos_total.html", stats_cargos=stats_cargos)


@app.route("/excluir_ficha/<int:id>", methods=["GET", "POST"])
@login_required
@security.require_permission("delete_permanently")
def excluir_ficha(id):
    ficha = db.session.get(Funcionario, id)
    if ficha:
        nome = ficha.nome
        sec_id = ficha.secretaria_id
        HistoricoLotacao.query.filter_by(funcionario_id=id).delete()
        db.session.delete(ficha)
        db.session.commit()
        registrar_log("EXCLUIU FICHA", nome, nivel="WARN", secretaria_id=sec_id)
        flash("Ficha excluída.", "success")
    return redirect(url_for("sistema"))


@app.route("/admin/update_user", methods=["POST"])
@login_required
@security.require_permission("manage_users")
def update_user():
    user_id = request.form.get("user_id")
    u = db.session.get(User, user_id)

    if u:
        new_username = (request.form.get("username") or "").strip()
        if new_username and new_username != u.username:
            if User.query.filter_by(username=new_username).first():
                flash("Nome de usuário já existe!", "error")
                return redirect(url_for("admin_dashboard", tab="config"))
            u.username = new_username

        new_password = request.form.get("password") or ""
        if new_password:
            ok_pwd, msg_pwd = security.validate_password_strength(new_password)
            if not ok_pwd:
                flash(f"Senha fraca: {msg_pwd}", "error")
                return redirect(url_for("admin_dashboard", tab="config"))
            u.set_password(new_password)
            u.pergunta_troca_senha_exibida = False

        if request.form.get("nome_completo") is not None:
            u.nome_completo = (request.form.get("nome_completo") or "").strip().upper() or None
        if request.form.get("email") is not None:
            u.email = (request.form.get("email") or "").strip() or None

        sec_id = request.form.get("secretaria_id", type=int)
        local_id = request.form.get("local_trabalho_id", type=int)
        role = (request.form.get("role") or "").strip()

        if role:
            norm_role = security.LEGACY_ROLE_MAP.get(role, role)
            if norm_role in security.ROLE_METADATA:
                u.role = norm_role
                u.is_admin = norm_role == "super_admin"
                if norm_role in ("super_admin", "prefeito", "estrategia_eleitoral", "auditor"):
                    u.secretaria_id = sec_id or None
                    u.local_trabalho_id = None
                else:
                    if sec_id:
                        u.secretaria_id = sec_id
                    u.local_trabalho_id = local_id if norm_role == "chefe_unidade" else None
        elif sec_id:
            u.secretaria_id = sec_id

        if "ativo" in request.form and u.username != "admin":
            u.ativo = request.form.get("ativo") in ("1", "true", "on", "sim")

        db.session.commit()
        registrar_log("EDITOU USUÁRIO", f"{u.username} [{u.normalized_role}]", secretaria_id=u.secretaria_id)
        flash("Usuário atualizado com sucesso!", "success")

    return redirect(url_for("admin_dashboard", tab="config"))


@app.route("/admin/desbloquear_usuario/<int:user_id>", methods=["POST"])
@login_required
@security.require_permission("manage_users")
def desbloquear_usuario(user_id):
    u = db.session.get(User, user_id)
    if u:
        u.tentativas_falhas = 0
        u.bloqueado_ate = None
        u.ativo = True
        db.session.commit()
        registrar_log("DESBLOQUEOU USUÁRIO", u.username, nivel="SECURITY", secretaria_id=u.secretaria_id)
        flash(f"Conta de '{u.username}' desbloqueada e ativada.", "success")
    return redirect(url_for("admin_dashboard", tab="config"))


@app.route("/admin/delete_user/<int:user_id>", methods=["GET", "POST"])
@login_required
@security.require_permission("manage_users")
def delete_user(user_id):
    u = db.session.get(User, user_id)
    if u and u.username != "admin" and u.id != current_user.id:
        nome_u = u.username
        db.session.delete(u)
        db.session.commit()
        registrar_log("EXCLUIU USUÁRIO", nome_u, nivel="WARN")
        flash("Usuário excluído.", "success")
    return redirect(url_for("admin_dashboard", tab="config"))


@app.route("/admin/delete_secretaria/<int:sec_id>", methods=["GET", "POST"])
@login_required
@security.require_permission("manage_secretarias")
def delete_secretaria(sec_id):
    if (
        User.query.filter_by(secretaria_id=sec_id).first()
        or Funcionario.query.filter_by(secretaria_id=sec_id).first()
        or LocalTrabalho.query.filter_by(secretaria_id=sec_id).first()
    ):
        flash("Erro: Existem usuários, servidores ou locais vinculados a esta secretaria.", "error")
    else:
        s = db.session.get(Secretaria, sec_id)
        if s:
            nome_s = s.nome
            db.session.delete(s)
            db.session.commit()
            registrar_log("EXCLUIU SECRETARIA", nome_s, nivel="WARN")
            flash("Secretaria excluída.", "success")
    return redirect(url_for("admin_dashboard", tab="config"))


@app.route("/admin/editar_funcao", methods=["POST"])
@login_required
@security.require_permission("manage_funcoes")
def editar_funcao():
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


@app.route("/admin/delete_funcao/<int:id>", methods=["GET", "POST"])
@login_required
@security.require_permission("manage_funcoes")
def delete_funcao(id):
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


@app.route("/admin/delete_local/<int:id>", methods=["GET", "POST"])
@login_required
@security.require_permission("manage_locais")
def delete_local(id):
    l = db.session.get(LocalTrabalho, id)
    if l and not security.can_access_record(current_user, l):
        registrar_violacao_acesso(f"Excluir local_id={id}")
        flash("Acesso negado: local pertence a outra secretaria.", "error")
        return redirect(url_for("admin_dashboard") + "?tab=config")
    if Funcionario.query.filter_by(local_trabalho_id=id).first():
        flash("Erro: Existem funcionários neste local.", "error")
    else:
        if l:
            db.session.delete(l)
            db.session.commit()
            flash("Local de trabalho excluído.", "success")
    return redirect(url_for("admin_dashboard") + "?tab=config")


@app.route("/admin/delete_padrinho/<int:id>", methods=["GET", "POST"])
@login_required
@security.require_permission("manage_padrinhos")
def delete_padrinho(id):
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
@security.require_permission("export_rh")
def exportar_excel():
    is_global = security.has_global_scope(current_user)
    filtro_secretaria = request.args.get("secretaria_id") if is_global else None
    filtro_vinculo = request.args.get("tipo_vinculo")
    filtro_indicacao = request.args.get("padrinho_id") if security.has_permission(current_user, "view_padrinhos") else None
    filtro_funcao = request.args.get("funcao_id")
    filtro_local = request.args.get("local_trabalho_id")

    query = security.scope_query(
        Funcionario.query.filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None))),
        Funcionario,
        current_user,
    )
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
@security.require_permission("view_rh")
def sistema():
    is_global = security.has_global_scope(current_user)
    can_write = security.has_permission(current_user, "write_rh")

    secretarias_opcoes = (
        Secretaria.query.order_by(Secretaria.nome).all()
        if is_global
        else []
    )
    funcoes_opcoes = Funcao.query.order_by(Funcao.nome).all()
    locais_opcoes = security.scope_query(
        LocalTrabalho.query, LocalTrabalho, current_user
    ).order_by(LocalTrabalho.nome).all()
    padrinhos_opcoes = Padrinho.query.order_by(Padrinho.nome).all()

    nome_secretaria_atual = (
        current_user.secretaria.nome if current_user.secretaria else "Sem Secretaria"
    )
    if is_global:
        nome_secretaria_atual = f"{current_user.role_label.upper()} (VISÃO GLOBAL)"

    if request.method == "POST":
        if not can_write:
            registrar_violacao_acesso("POST /sistema sem permissao write_rh")
            flash("Acesso negado: seu perfil é somente leitura para fichas cadastrais.", "error")
            return redirect(url_for("sistema"))

        is_indicacao = True if request.form.get("foi_indicacao") == "sim" else False
        padrinho_id = (
            request.form.get("padrinho_id")
            if is_indicacao and request.form.get("padrinho_id")
            else None
        )

        # LÓGICA DE SECRETARIA (FORÇA ISOLAMENTO PARA NÃO-GLOBAIS)
        if is_global:
            sec_id = request.form.get("secretaria_id")
            if not sec_id:
                flash("Selecione a Secretaria!", "error")
                return redirect(url_for("sistema"))
            sec_obj = db.session.get(Secretaria, int(sec_id))
            if not sec_obj:
                flash("Secretaria inválida!", "error")
                return redirect(url_for("sistema"))
            lotacao_texto = sec_obj.nome
        else:
            if not current_user.secretaria_id:
                flash("Seu usuário não possui Secretaria vinculada. Contate o Master TI.", "error")
                return redirect(url_for("sistema"))
            sec_id = current_user.secretaria_id
            lotacao_texto = (
                current_user.secretaria.nome
                if current_user.secretaria
                else "ADMINISTRAÇÃO"
            )

        # Valida se o local_trabalho_id escolhido pertence à secretaria (para não-globais)
        local_id_form = request.form.get("local_trabalho_id") or None
        if local_id_form and not is_global:
            loc_check = db.session.get(LocalTrabalho, int(local_id_form))
            if loc_check and loc_check.secretaria_id and int(loc_check.secretaria_id) != int(sec_id):
                registrar_violacao_acesso(f"Tentou vincular servidor a local_id={local_id_form} de outra secretaria")
                flash("Acesso negado: o local de trabalho selecionado não pertence à sua secretaria.", "error")
                return redirect(url_for("sistema"))

        cpf_raw_form = request.form.get("cpf") or ""
        cpf_normalizado = normalizar_cpf(cpf_raw_form)
        remuneracao_raw = request.form.get("remuneracao") or ""

        dados_form = {
            "nome": (request.form.get("nome") or "").strip().upper(),
            "num_vinculo": request.form.get("num_vinculo"),
            "cpf": cpf_raw_form.strip(),
            "cpf_limpo": cpf_normalizado or None,
            "rg": request.form.get("rg"),
            "data_expedicao_rg": parse_date(request.form.get("data_expedicao_rg")),
            "data_nasc": parse_date(request.form.get("data_nasc")),
            "pis": request.form.get("pis"),
            "titulo_eleitor": request.form.get("titulo_eleitor"),
            "zona_eleitoral": request.form.get("zona_eleitoral"),
            "secao_eleitoral": request.form.get("secao_eleitoral"),
            "mae": (request.form.get("mae") or "").upper(),
            "nacionalidade": request.form.get("nacionalidade"),
            "estado_civil": request.form.get("estado_civil"),
            "telefone": request.form.get("telefone"),
            "email": request.form.get("email"),
            "endereco": (request.form.get("endereco") or "").upper(),
            "funcao_id": request.form.get("funcao_id") or None,
            "local_trabalho_id": local_id_form,
            "tipo_vinculo": request.form.get("tipo_vinculo"),
            "classe": request.form.get("classe"),
            "contracheque": request.form.get("contracheque"),
            "remuneracao": remuneracao_raw,
            "remuneracao_valor": security.parse_remuneracao_float(remuneracao_raw),
            "jornada_trabalho": request.form.get("jornada_trabalho"),
            "dt_inicio": parse_date(request.form.get("dt_inicio")),
            "dt_termino": parse_date(request.form.get("dt_termino")),
            "banco": request.form.get("banco"),
            "agencia": request.form.get("agencia"),
            "conta": request.form.get("conta"),
            "tipo_conta": request.form.get("tipo_conta"),
            "foi_indicacao": is_indicacao,
            "padrinho_id": padrinho_id,
            "secretaria_id": int(sec_id),
            "lotacao": lotacao_texto,
            "crianca_assistida": (
                request.form.get("crianca_assistida").strip().upper()
                if request.form.get("crianca_assistida")
                and request.form.get("crianca_assistida").strip()
                else None
            ),
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

        if not dados_form.get("cpf"):
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

        if not func_id:
            dados_form["num_vinculo"] = gerar_proximo_vinculo()

        # Validação de CPF duplicado (indexada e respeitando sigilo entre secretarias!)
        cpf_duplicado = False
        if cpf_normalizado and len(cpf_normalizado) == 11:
            q_cpf = Funcionario.query.filter(
                (Funcionario.cpf_limpo == cpf_normalizado) | (Funcionario.cpf == dados_form["cpf"]),
                (Funcionario.ativo == True) | (Funcionario.ativo.is_(None)),
            )
            if func_id:
                q_cpf = q_cpf.filter(Funcionario.id != int(func_id))
            encontrados_cpf = q_cpf.all()

            mesma_sec = [f for f in encontrados_cpf if int(f.secretaria_id) == int(sec_id)]
            outra_sec = [f for f in encontrados_cpf if int(f.secretaria_id) != int(sec_id)]

            if mesma_sec:
                cpf_duplicado = True
                nomes_duplicados = [f.nome for f in mesma_sec]
                flash(
                    f'⚠️ ATENÇÃO: Este CPF já está cadastrado nesta secretaria para: {", ".join(nomes_duplicados)}.',
                    "error",
                )
            elif outra_sec:
                cpf_duplicado = True
                # Alerta silencioso ao Gabinete/Prefeito sem vazar dados da outra pasta para o operador!
                outras_secs_nomes = ", ".join({f.secretaria.nome for f in outra_sec if f.secretaria})
                registrar_log(
                    "ALERTA_ACUMULO_CPF",
                    f"CPF {dados_form['cpf']} ({dados_form['nome']}) cadastrado em {lotacao_texto} mas já ativo em: {outras_secs_nomes}",
                    nivel="SECURITY",
                    secretaria_id=None,
                )
                if is_global:
                    flash(
                        f"⚠️ ALERTA DE ACÚMULO: Este CPF já possui vínculo ativo em outra secretaria ({outras_secs_nomes}).",
                        "error",
                    )
                else:
                    flash(
                        "⚠️ AVISO DE GOVERNANÇA: Este CPF já possui vínculo ativo em outro órgão do Município. Um alerta automático foi enviado à Administração/Gabinete.",
                        "error",
                    )

        if func_id:
            funcionario = db.session.get(Funcionario, func_id)
            if not funcionario:
                flash("Servidor não encontrado.", "error")
                return redirect(url_for("sistema"))
            # BLOQUEIO ESTRITO ANTI-IDOR: impede editar ficha de outra secretaria!
            if not security.can_access_record(current_user, funcionario):
                registrar_violacao_acesso(f"Tentativa de editar funcionario_id={func_id} de outra secretaria")
                flash("Acesso negado: você não tem permissão para editar servidores de outra secretaria.", "error")
                return redirect(url_for("sistema"))

            mudou_local = str(funcionario.local_trabalho_id) != str(dados_form["local_trabalho_id"])
            mudou_sec = str(funcionario.secretaria_id) != str(sec_id)
            mudou_funcao = str(funcionario.funcao_id) != str(dados_form["funcao_id"])

            if mudou_local or mudou_sec or mudou_funcao:
                novo_local_obj = db.session.get(LocalTrabalho, dados_form["local_trabalho_id"]) if dados_form["local_trabalho_id"] else None
                historico = HistoricoLotacao(
                    funcionario_id=funcionario.id,
                    antiga_secretaria=funcionario.lotacao,
                    antigo_local=(funcionario.local_trabalho.nome if funcionario.local_trabalho else "N/A"),
                    antiga_funcao=(funcionario.funcao.nome if funcionario.funcao else "N/A"),
                    quem_mudou_id=current_user.id,
                )
                db.session.add(historico)
                registrar_log(
                    "MOVIMENTOU",
                    f"{funcionario.nome} -> {novo_local_obj.nome if novo_local_obj else 'N/A'}",
                    secretaria_id=int(sec_id),
                )
            else:
                registrar_log("EDITOU", funcionario.nome, secretaria_id=int(sec_id))

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
            registrar_log("CRIOU FICHA", f"{novo_func.nome} ({lotacao_texto})", secretaria_id=int(sec_id))
            if not cpf_duplicado:
                flash("Ficha criada com sucesso!", "success")

        return redirect(url_for("sistema"))

    query = security.scope_query(
        Funcionario.query.filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None))),
        Funcionario,
        current_user,
    )
    lista_funcionarios = query.order_by(Funcionario.id.desc()).all()
    proximo_vinculo_form = gerar_proximo_vinculo()

    funcao_apoio = Funcao.query.filter(
        Funcao.nome.in_(
            [
                "PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)",
                "PROFISSIONAL DE APOIO / CUIDADOR",
            ]
        )
    ).first()
    funcao_apoio_id = funcao_apoio.id if funcao_apoio else None

    contratos_gerados_todos = security.scope_query(
        ContratoGerado.query, ContratoGerado, current_user
    ).all()
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
        is_admin=security.is_super_admin(current_user),
        role=current_user.normalized_role,
        proximo_vinculo_form=proximo_vinculo_form,
        funcao_apoio_id=funcao_apoio_id,
        mapa_contratos_gerados=mapa_contratos_gerados,
    )


def create_admin():
    with app.app_context():
        db.create_all()
        user = User.query.filter_by(username="admin").first()
        if not user:
            sec_adm = Secretaria.query.filter_by(nome="PREFEITURA MUNICIPAL").first()
            if not sec_adm:
                sec_adm = Secretaria(nome="PREFEITURA MUNICIPAL", sigla="PMV", ativa=True)
                db.session.add(sec_adm)
                db.session.commit()

            senha_inicial = os.getenv("ADMIN_INITIAL_PASSWORD", "Mudar123@")

            user = User(
                username="admin",
                nome_completo="ADMINISTRADOR MASTER",
                is_admin=True,
                role="super_admin",
                secretaria_id=sec_adm.id,
                ativo=True,
            )
            user.set_password(senha_inicial)
            db.session.add(user)
            db.session.commit()
            print(f"ADMINISTRADOR CRIADO COM SENHA INICIAL: {senha_inicial}")


def atualizar_schema():
    """Migração aditiva segura para SQLite e PostgreSQL (Railway) — preserva 100% dos dados existentes."""
    with app.app_context():
        with db.engine.connect() as conn:
            # 1. Novas colunas por tabela (100% aditivas)
            migracoes_colunas = {
                "secretaria": [
                    ("sigla", "VARCHAR(20)"),
                    ("cnpj", "VARCHAR(25)"),
                    ("endereco", "VARCHAR(255)"),
                    ("telefone", "VARCHAR(30)"),
                    ("email", "VARCHAR(120)"),
                    ("secretario_nome", "VARCHAR(150)"),
                    ("secretario_cargo", "VARCHAR(120)"),
                    ("secretario_cpf", "VARCHAR(30)"),
                    ("secretario_portaria", "VARCHAR(100)"),
                    ("teto_comissionados", "INTEGER DEFAULT 0"),
                    ("teto_folha_mensal", "FLOAT DEFAULT 0"),
                    ("ativa", "BOOLEAN DEFAULT TRUE"),
                ],
                "local_trabalho": [
                    ("secretaria_id", "INTEGER"),
                    ("tipo_unidade", "VARCHAR(40) DEFAULT 'UNIDADE'"),
                    ("ativa", "BOOLEAN DEFAULT TRUE"),
                    ("latitude", "FLOAT"),
                    ("longitude", "FLOAT"),
                    ("raio_permitido", "INTEGER DEFAULT 50"),
                ],
                "funcionario": [
                    ("padrinho_id", "INTEGER"),
                    ("funcao_id", "INTEGER"),
                    ("local_trabalho_id", "INTEGER"),
                    ("validado", "BOOLEAN DEFAULT FALSE"),
                    ("data_expedicao_rg", "DATE"),
                    ("jornada_trabalho", "VARCHAR(50)"),
                    ("crianca_assistida", "VARCHAR(150)"),
                    ("foto_biometria", "TEXT"),
                    ("foto_path", "VARCHAR(255)"),
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
                    ("ativo", "BOOLEAN DEFAULT TRUE"),
                    ("cpf_limpo", "VARCHAR(11)"),
                    ("remuneracao_valor", "FLOAT DEFAULT 0"),
                ],
                "rescisao_historico": [
                    ("secretaria_id", "INTEGER"),
                    ("rg", "VARCHAR(20)"),
                    ("endereco", "VARCHAR(200)"),
                    ("num_contrato", "VARCHAR(50)"),
                ],
                "log_auditoria": [
                    ("secretaria_id", "INTEGER"),
                    ("nivel", "VARCHAR(20) DEFAULT 'INFO'"),
                    ("tabela_afetada", "VARCHAR(50)"),
                    ("registro_id", "INTEGER"),
                    ("dados_antigos", "TEXT"),
                    ("dados_novos", "TEXT"),
                    ("ip_origem", "VARCHAR(50)"),
                    ("user_agent", "VARCHAR(255)"),
                    ("rota_acessada", "VARCHAR(255)"),
                ],
                "contrato_gerado": [
                    ("secretaria_id", "INTEGER"),
                    ("editado", "BOOLEAN DEFAULT FALSE"),
                    ("motivo_edicao", "TEXT"),
                    ("data_edicao", "TIMESTAMP"),
                    ("quem_editou_id", "INTEGER"),
                ],
                '"user"': [
                    ("nome_completo", "VARCHAR(150)"),
                    ("email", "VARCHAR(120)"),
                    ("local_trabalho_id", "INTEGER"),
                    ("ativo", "BOOLEAN DEFAULT TRUE"),
                    ("tentativas_falhas", "INTEGER DEFAULT 0"),
                    ("bloqueado_ate", "TIMESTAMP"),
                    ("ultimo_login_em", "TIMESTAMP"),
                    ("ultimo_login_ip", "VARCHAR(50)"),
                    ("precisa_trocar_senha", "BOOLEAN DEFAULT FALSE"),
                    ("termo_aceito", "BOOLEAN DEFAULT FALSE"),
                    ("termo_aceito_em", "TIMESTAMP"),
                    ("pergunta_troca_senha_exibida", "BOOLEAN DEFAULT FALSE"),
                ],
            }

            for tabela, colunas in migracoes_colunas.items():
                for col, tipo in colunas:
                    try:
                        conn.execute(text(f"ALTER TABLE {tabela} ADD COLUMN {col} {tipo}"))
                        conn.commit()
                    except Exception:
                        conn.rollback()

            # Expande colunas em PostgreSQL (ignorado no SQLite)
            for sql_alter in [
                "ALTER TABLE log_auditoria ALTER COLUMN acao TYPE VARCHAR(255)",
                "ALTER TABLE log_auditoria ALTER COLUMN alvo TYPE VARCHAR(500)",
                'ALTER TABLE "user" ALTER COLUMN role TYPE VARCHAR(40)',
            ]:
                try:
                    conn.execute(text(sql_alter))
                    conn.commit()
                except Exception:
                    conn.rollback()

            # Índices de performance
            for sql_idx in [
                "CREATE INDEX IF NOT EXISTS idx_funcionario_cpf_limpo ON funcionario (cpf_limpo)",
                "CREATE INDEX IF NOT EXISTS idx_funcionario_sec_ativo ON funcionario (secretaria_id, ativo)",
                "CREATE INDEX IF NOT EXISTS idx_local_trabalho_sec ON local_trabalho (secretaria_id)",
                "CREATE INDEX IF NOT EXISTS idx_log_auditoria_sec ON log_auditoria (secretaria_id)",
            ]:
                try:
                    conn.execute(text(sql_idx))
                    conn.commit()
                except Exception:
                    conn.rollback()

            # Valores padrão sem NULL
            for sql_upd in [
                "UPDATE funcionario SET ativo = TRUE WHERE ativo IS NULL",
                "UPDATE secretaria SET ativa = TRUE WHERE ativa IS NULL",
                "UPDATE local_trabalho SET ativa = TRUE WHERE ativa IS NULL",
                "UPDATE local_trabalho SET tipo_unidade = 'UNIDADE' WHERE tipo_unidade IS NULL",
                'UPDATE "user" SET ativo = TRUE WHERE ativo IS NULL',
                'UPDATE "user" SET tentativas_falhas = 0 WHERE tentativas_falhas IS NULL',
                'UPDATE "user" SET pergunta_troca_senha_exibida = FALSE WHERE pergunta_troca_senha_exibida IS NULL',
                "UPDATE log_auditoria SET nivel = 'INFO' WHERE nivel IS NULL",
            ]:
                try:
                    conn.execute(text(sql_upd))
                    conn.commit()
                except Exception:
                    conn.rollback()

            # Migração automática do nome da Função de Apoio
            try:
                conn.execute(
                    text(
                        "UPDATE funcao SET nome = 'PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)' "
                        "WHERE nome IN ('PROFISSIONAL DE APOIO / CUIDADOR', 'PROFISSIONAL DE APOIO (CUIDADOR)') "
                        "AND NOT EXISTS (SELECT 1 FROM funcao WHERE nome = 'PROFISSIONAL DE APOIO ESCOLAR (CUIDADOR)')"
                    )
                )
                conn.commit()
            except Exception:
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
            except Exception:
                conn.rollback()

        # Garante novas tabelas (ex.: backup_historico)
        try:
            db.create_all()
        except Exception:
            pass

        # --- BACKFILL AUTOMÁTICO SEGURO DOS REGISTROS LEGADOS (2026 -> 2027) ---
        try:
            # 1. Preenche cpf_limpo e remuneracao_valor em funcionários legados
            funcs_sem_backfill = Funcionario.query.filter(
                (Funcionario.cpf_limpo.is_(None))
                | ((Funcionario.remuneracao.isnot(None)) & ((Funcionario.remuneracao_valor.is_(None)) | (Funcionario.remuneracao_valor == 0)))
            ).all()
            alterou_func = False
            for f in funcs_sem_backfill:
                if f.cpf and not f.cpf_limpo:
                    f.cpf_limpo = normalizar_cpf(f.cpf)[:11] or None
                    alterou_func = True
                if f.remuneracao and (not f.remuneracao_valor):
                    val = security.parse_remuneracao_float(f.remuneracao)
                    if val > 0:
                        f.remuneracao_valor = val
                        alterou_func = True
            if alterou_func:
                db.session.commit()

            # Descobre secretaria predominante (ex.: Educação) para vincular registros órfãos antigos
            sec_predominante_row = (
                db.session.query(Funcionario.secretaria_id, func.count(Funcionario.id))
                .group_by(Funcionario.secretaria_id)
                .order_by(func.count(Funcionario.id).desc())
                .first()
            )
            default_sec_id = sec_predominante_row[0] if sec_predominante_row else None
            if default_sec_id is None:
                first_sec = Secretaria.query.order_by(Secretaria.id.asc()).first()
                default_sec_id = first_sec.id if first_sec else None

            # 2. Vincula LocalTrabalho sem secretaria_id à secretaria predominante de seus servidores
            locais_orfaos = LocalTrabalho.query.filter(LocalTrabalho.secretaria_id.is_(None)).all()
            if locais_orfaos and default_sec_id:
                for loc in locais_orfaos:
                    row_sec = (
                        db.session.query(Funcionario.secretaria_id, func.count(Funcionario.id))
                        .filter(Funcionario.local_trabalho_id == loc.id)
                        .group_by(Funcionario.secretaria_id)
                        .order_by(func.count(Funcionario.id).desc())
                        .first()
                    )
                    loc.secretaria_id = row_sec[0] if row_sec else default_sec_id
                db.session.commit()

            # 3. Vincula ContratoGerado sem secretaria_id
            contratos_orfaos = ContratoGerado.query.filter(ContratoGerado.secretaria_id.is_(None)).all()
            if contratos_orfaos and default_sec_id:
                for cg in contratos_orfaos:
                    sec_c = None
                    if cg.funcionario_id:
                        f_c = db.session.get(Funcionario, cg.funcionario_id)
                        if f_c:
                            sec_c = f_c.secretaria_id
                    if not sec_c and cg.contratado_cpf:
                        cpf_c = normalizar_cpf(cg.contratado_cpf)
                        f_c = Funcionario.query.filter_by(cpf_limpo=cpf_c).first()
                        if f_c:
                            sec_c = f_c.secretaria_id
                    cg.secretaria_id = sec_c or default_sec_id
                db.session.commit()

            # 4. Vincula RescisaoHistorico sem secretaria_id
            rescisoes_orfas = RescisaoHistorico.query.filter(RescisaoHistorico.secretaria_id.is_(None)).all()
            if rescisoes_orfas and default_sec_id:
                for rh in rescisoes_orfas:
                    sec_r = None
                    if rh.cpf:
                        cpf_r = normalizar_cpf(rh.cpf)
                        f_r = Funcionario.query.filter_by(cpf_limpo=cpf_r).first()
                        if f_r:
                            sec_r = f_r.secretaria_id
                    rh.secretaria_id = sec_r or default_sec_id
                db.session.commit()

            # 5. Vincula OrganogramaExercicio sem secretaria_id
            orgs_orfaos = OrganogramaExercicio.query.filter(OrganogramaExercicio.secretaria_id.is_(None)).all()
            if orgs_orfaos and default_sec_id:
                for org in orgs_orfaos:
                    org.secretaria_id = default_sec_id
                db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Aviso backfill seguro: {e}")


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
@security.require_permission("view_contratos", api=True)
def api_proximo_numero_contrato():
    ano = request.args.get("ano", type=int) or datetime.now().year
    sec_id = (
        request.args.get("secretaria_id", type=int)
        if security.has_global_scope(current_user)
        else current_user.secretaria_id
    )
    proximo = gerar_proximo_numero_contrato(ano, secretaria_id=sec_id)
    return {"num_contrato": proximo}


@app.route("/gerar_contrato", methods=["POST"])
@login_required
@security.require_permission("manage_contratos", api=True)
def processar_gerar_contrato():
    try:
        funcionario_id = request.form.get("funcionario_id", type=int)
        contratado_cpf = request.form.get("contratado_cpf", "").strip()
        contratado_nome = request.form.get("contratado_nome", "").strip()

        func_obj = db.session.get(Funcionario, funcionario_id) if funcionario_id else None
        if func_obj and not security.can_access_record(current_user, func_obj):
            registrar_violacao_acesso(f"Gerar contrato funcionario_id={funcionario_id}")
            return {"success": False, "message": "Acesso negado: servidor pertence a outra secretaria."}, 403

        sec_id_contrato = (
            func_obj.secretaria_id
            if func_obj
            else (request.form.get("secretaria_id", type=int) if security.has_global_scope(current_user) else current_user.secretaria_id)
        )
        sec_obj = db.session.get(Secretaria, sec_id_contrato) if sec_id_contrato else None
        rep_padrao = obter_dados_representante_secretaria(sec_obj)

        # Verifica duplicidade de contrato no mesmo exercício/servidor
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
                "message": f"Este servidor já possui um contrato gerado (Nº {existente.num_contrato}). Utilize a opção de edição na página 'Contratos Gerados' para alterá-lo.",
                "existente_num": existente.num_contrato,
                "existente_id": existente.id
            }, 400

        num_contrato = request.form.get("num_contrato")
        dt_inicio_str = request.form.get("dt_inicio")
        dt_termino_str = request.form.get("dt_termino")
        dt_assinatura_str = request.form.get("dt_assinatura")

        contratado_rg = request.form.get("contratado_rg", "").strip()
        contratado_nacionalidade = request.form.get("contratado_nacionalidade", "brasileiro(a)").strip()
        contratado_naturalidade = request.form.get("contratado_naturalidade", "piauiense").strip()
        contratado_estado_civil = request.form.get("contratado_estado_civil", "solteiro(a)").strip()
        contratado_endereco = request.form.get("contratado_endereco", "").strip()

        funcao_nome = request.form.get("funcao_nome", "").strip()
        jornada_trabalho = request.form.get("jornada_trabalho", "").strip()
        remuneracao = request.form.get("remuneracao", "").strip()
        remuneracao_extenso = request.form.get("remuneracao_extenso", "").strip()

        representante_nome = (request.form.get("representante_nome") or rep_padrao["nome"]).strip()
        representante_cargo = (request.form.get("representante_cargo") or rep_padrao["cargo"]).strip()
        representante_rg_cpf = (request.form.get("representante_rg_cpf") or rep_padrao["cpf"]).strip()
        representante_endereco = (request.form.get("representante_endereco") or rep_padrao["endereco"]).strip()

        dt_admissao_ficha = func_obj.dt_inicio if (func_obj and func_obj.dt_inicio) else None
        dt_inicio = parse_date(dt_inicio_str) if dt_inicio_str else (dt_admissao_ficha or date.today())
        dt_termino = parse_date(dt_termino_str) if dt_termino_str else None
        dt_assinatura = parse_date(dt_assinatura_str) if dt_assinatura_str else (dt_inicio or dt_admissao_ficha or date.today())
        ano_exercicio = dt_inicio.year if dt_inicio else datetime.now().year

        if not num_contrato:
            num_contrato = gerar_proximo_numero_contrato(ano_exercicio, secretaria_id=sec_id_contrato)

        novo_contrato = ContratoGerado(
            secretaria_id=sec_id_contrato,
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

        registrar_log("Gerou Contrato", f"Contrato Nº {num_contrato} - {contratado_nome}", secretaria_id=sec_id_contrato)

        return {
            "success": True,
            "contrato_id": novo_contrato.id,
            "view_url": url_for("visualizar_contrato_documento", id=novo_contrato.id)
        }
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route("/contrato/alterar_data_assinatura/<int:id>", methods=["POST"])
@login_required
@security.require_permission("manage_contratos", api=True)
def alterar_data_assinatura_contrato(id):
    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        return {"success": False, "message": "Contrato não encontrado."}, 404
    if not security.can_access_record(current_user, contrato):
        registrar_violacao_acesso(f"Alterar assinatura contrato_id={id}")
        return {"success": False, "message": "Acesso negado: contrato pertence a outra secretaria."}, 403

    data_json = request.get_json(silent=True) or {}
    dt_assinatura_str = (
        request.form.get("dt_assinatura")
        or data_json.get("dt_assinatura")
        or ""
    ).strip()

    nova_dt = parse_date(dt_assinatura_str)
    if not nova_dt:
        return {"success": False, "message": "Data de assinatura inválida."}, 400

    try:
        contrato.dt_assinatura = nova_dt
        db.session.commit()
        return {
            "success": True,
            "contrato_id": contrato.id,
            "dt_assinatura_iso": nova_dt.isoformat(),
            "dt_assinatura_formatada": nova_dt.strftime("%d/%m/%Y"),
            "dt_assinatura_extenso": formatar_data_extenso(nova_dt),
        }
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500


@app.route("/contrato/editar/<int:id>", methods=["POST"])
@login_required
@security.require_permission("manage_contratos", api=True)
def editar_contrato(id):
    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        return {"success": False, "message": "Contrato não encontrado."}, 404
    if not security.can_access_record(current_user, contrato):
        registrar_violacao_acesso(f"Editar contrato_id={id}")
        return {"success": False, "message": "Acesso negado: contrato pertence a outra secretaria."}, 403

    motivo = request.form.get("motivo_edicao", "").strip()

    try:
        novo_nome = request.form.get("contratado_nome", "").strip()
        novo_cpf = request.form.get("contratado_cpf", "").strip()
        novo_rg = request.form.get("contratado_rg", "").strip()
        novo_nac = request.form.get("contratado_nacionalidade", "brasileiro(a)").strip()
        novo_nat = request.form.get("contratado_naturalidade", "piauiense").strip()
        novo_ec = request.form.get("contratado_estado_civil", "solteiro(a)").strip()
        novo_end = request.form.get("contratado_endereco", "").strip()

        nova_funcao = request.form.get("funcao_nome", "").strip()
        nova_jornada = request.form.get("jornada_trabalho", "").strip()
        nova_rem = request.form.get("remuneracao", "").strip()
        nova_rem_ext = request.form.get("remuneracao_extenso", "").strip()

        dt_inicio_str = request.form.get("dt_inicio")
        dt_termino_str = request.form.get("dt_termino")
        dt_assinatura_str = request.form.get("dt_assinatura")

        novo_dt_inicio = parse_date(dt_inicio_str) if dt_inicio_str else contrato.dt_inicio
        novo_dt_termino = parse_date(dt_termino_str) if dt_termino_str else contrato.dt_termino
        novo_dt_assinatura = parse_date(dt_assinatura_str) if dt_assinatura_str else contrato.dt_assinatura

        novo_rep_nome = request.form.get("representante_nome", contrato.representante_nome or "").strip()
        novo_rep_cargo = request.form.get("representante_cargo", contrato.representante_cargo or "").strip()
        novo_rep_cpf = request.form.get("representante_rg_cpf", contrato.representante_rg_cpf or "").strip()
        novo_rep_end = request.form.get("representante_endereco", contrato.representante_endereco or "").strip()

        alterou_outros_campos = any([
            novo_nome != (contrato.contratado_nome or "").strip(),
            novo_cpf != (contrato.contratado_cpf or "").strip(),
            novo_rg != (contrato.contratado_rg or "").strip(),
            novo_nac != (contrato.contratado_nacionalidade or "brasileiro(a)").strip(),
            novo_nat != (contrato.contratado_naturalidade or "piauiense").strip(),
            novo_ec != (contrato.contratado_estado_civil or "solteiro(a)").strip(),
            novo_end != (contrato.contratado_endereco or "").strip(),
            nova_funcao != (contrato.funcao_nome or "").strip(),
            nova_jornada != (contrato.jornada_trabalho or "").strip(),
            nova_rem != (contrato.remuneracao or "").strip(),
            nova_rem_ext != (contrato.remuneracao_extenso or "").strip(),
            novo_dt_inicio != contrato.dt_inicio,
            novo_dt_termino != contrato.dt_termino,
            novo_rep_nome != (contrato.representante_nome or "").strip(),
            novo_rep_cargo != (contrato.representante_cargo or "").strip(),
            novo_rep_cpf != (contrato.representante_rg_cpf or "").strip(),
            novo_rep_end != (contrato.representante_endereco or "").strip(),
        ])

        if alterou_outros_campos and not motivo:
            return {"success": False, "message": "É obrigatório informar o motivo da edição ao alterar dados cadastrais ou cláusulas do contrato."}, 400

        contrato.contratado_nome = novo_nome
        contrato.contratado_cpf = novo_cpf
        contrato.contratado_rg = novo_rg
        contrato.contratado_nacionalidade = novo_nac
        contrato.contratado_naturalidade = novo_nat
        contrato.contratado_estado_civil = novo_ec
        contrato.contratado_endereco = novo_end

        contrato.funcao_nome = nova_funcao
        contrato.jornada_trabalho = nova_jornada
        contrato.remuneracao = nova_rem
        contrato.remuneracao_extenso = nova_rem_ext

        contrato.dt_inicio = novo_dt_inicio
        contrato.dt_termino = novo_dt_termino
        contrato.dt_assinatura = novo_dt_assinatura

        contrato.representante_nome = novo_rep_nome
        contrato.representante_cargo = novo_rep_cargo
        contrato.representante_rg_cpf = novo_rep_cpf
        contrato.representante_endereco = novo_rep_end

        if alterou_outros_campos:
            contrato.editado = True
            contrato.motivo_edicao = motivo
            contrato.data_edicao = datetime.utcnow()
            contrato.quem_editou_id = current_user.id

        db.session.commit()

        if alterou_outros_campos:
            registrar_log("Editou Contrato", f"Contrato Nº {contrato.num_contrato} ({contrato.contratado_nome}) - Motivo: {motivo}", secretaria_id=contrato.secretaria_id)

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
@security.require_permission("view_contratos")
def pagina_contratos():
    historico = security.scope_query(
        ContratoGerado.query, ContratoGerado, current_user
    ).order_by(ContratoGerado.data_geracao.desc()).all()
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
@security.require_permission("view_contratos")
def visualizar_contrato_documento(id):
    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        return "Contrato não encontrado", 404
    if not security.can_access_record(current_user, contrato):
        registrar_violacao_acesso(f"Visualizar contrato_id={id}")
        return "Acesso negado", 403

    dt_ass = contrato.dt_assinatura or contrato.dt_inicio or (contrato.funcionario.dt_inicio if contrato.funcionario else None)

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
        "dt_assinatura_extenso": formatar_data_extenso(dt_ass),
        "dt_termino_formatada": contrato.dt_termino.strftime("%d/%m/%Y") if contrato.dt_termino else "",
        "dt_assinatura_formatada": dt_ass.strftime("%d/%m/%Y") if dt_ass else "",
        "dt_assinatura_iso": dt_ass.isoformat() if dt_ass else "",
        "representante_nome": contrato.representante_nome,
        "representante_cargo": contrato.representante_cargo,
        "representante_rg_cpf": contrato.representante_rg_cpf,
        "representante_endereco": contrato.representante_endereco,
    }

    return render_template("contrato_documento.html", contrato=contrato_dict)


@app.route("/contrato/extrato/<int:id>")
@login_required
@security.require_permission("view_contratos")
def visualizar_contrato_extrato(id):
    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        return "Contrato não encontrado", 404
    if not security.can_access_record(current_user, contrato):
        registrar_violacao_acesso(f"Visualizar extrato contrato_id={id}")
        return "Acesso negado", 403

    dt_ass_ext = contrato.dt_assinatura or contrato.dt_inicio or (contrato.funcionario.dt_inicio if contrato.funcionario else None)

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
        "dt_assinatura_formatada": dt_ass_ext.strftime("%d/%m/%Y") if dt_ass_ext else "",
        "dt_assinatura_iso": dt_ass_ext.isoformat() if dt_ass_ext else "",
    }

    return render_template("contrato_extrato.html", contrato=contrato_dict)


@app.route("/contrato/excluir/<int:id>", methods=["POST"])
@login_required
@security.require_permission("delete_permanently")
def excluir_contrato(id):
    contrato = db.session.get(ContratoGerado, id)
    if not contrato:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("pagina_contratos"))

    try:
        num = contrato.num_contrato
        nome = contrato.contratado_nome
        sec_id = contrato.secretaria_id
        db.session.delete(contrato)
        db.session.commit()
        registrar_log("Excluiu Contrato", f"Contrato Nº {num} - {nome}", nivel="WARN", secretaria_id=sec_id)
        flash(f"Contrato Nº {num} excluído com sucesso.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao excluir contrato: {str(e)}", "danger")

    return redirect(url_for("pagina_contratos"))


@app.route("/imprimir_encaminhamento/<int:id>")
@login_required
@security.require_permission("view_rh")
def imprimir_encaminhamento(id):
    funcionario = db.session.get(Funcionario, id)
    if not funcionario:
        return "Funcionário não encontrado", 404
    if not security.can_access_record(current_user, funcionario):
        registrar_violacao_acesso(f"Encaminhamento funcionario_id={id}")
        return "Acesso negado", 403

    hoje = datetime.now()
    meses = [
        "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
        "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro",
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
@security.require_permission("view_admin_panel")
def apoio_pedagogico():
    cuidadores = (
        security.scope_query(Funcionario.query.join(Funcao), Funcionario, current_user)
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
@security.require_permission("view_rh")
def gerenciar_fotos():
    funcionarios = security.scope_query(
        Funcionario.query, Funcionario, current_user
    ).order_by(Funcionario.nome).all()
    return render_template("fotos.html", funcionarios=funcionarios)


@app.route("/admin/folha_pagamento", methods=["GET"])
@login_required
@security.require_permission("view_folha")
def folha_pagamento():
    locais_trabalho = security.scope_query(
        LocalTrabalho.query, LocalTrabalho, current_user
    ).order_by(LocalTrabalho.nome).all()

    local_id_filtro = request.args.get("local_id")
    funcionarios_folha = []
    local_selecionado = None

    if local_id_filtro:
        local_selecionado = db.session.get(LocalTrabalho, local_id_filtro)
        if local_selecionado and security.can_access_record(current_user, local_selecionado):
            funcionarios_folha = (
                security.scope_query(
                    Funcionario.query.filter_by(local_trabalho_id=local_id_filtro),
                    Funcionario,
                    current_user,
                )
                .order_by(Funcionario.nome)
                .all()
            )
        else:
            local_selecionado = None

    return render_template(
        "folha_pagamento.html",
        locais_trabalho=locais_trabalho,
        funcionarios_folha=funcionarios_folha,
        local_selecionado=local_selecionado,
    )


@app.route("/admin/ponto", methods=["GET"])
@login_required
@security.require_permission("view_ponto")
def painel_ponto():
    """Painel interno para visualizar registros de ponto (isolado por secretaria/unidade)."""
    is_global = security.has_global_scope(current_user)
    secretaria_id = request.args.get("secretaria_id") if is_global else str(current_user.secretaria_id or "")
    busca_nome = request.args.get("busca_nome")
    mes = request.args.get("mes")
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

    query = security.scope_query(
        RegistroPonto.query.join(Funcionario), Funcionario, current_user
    )
    if secretaria_id and is_global:
        query = query.filter(Funcionario.secretaria_id == secretaria_id)
    if busca_nome:
        termo = f"%{busca_nome.upper()}%"
        query = query.filter(Funcionario.nome.like(termo))

    secretarias = (
        Secretaria.query.order_by(Secretaria.nome).all()
        if is_global
        else Secretaria.query.filter_by(id=current_user.secretaria_id).all()
    )

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
@security.require_permission("export_rh")
def exportar_migracao():
    funcionarios = security.scope_query(Funcionario.query, Funcionario, current_user).all()
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
@security.require_permission("move_servidores")
def movimentar_servidor():
    func_id = request.form.get("funcionario_id")
    nova_funcao_id = request.form.get("nova_funcao_id")
    novo_local_id = request.form.get("novo_local_id")

    funcionario = db.session.get(Funcionario, func_id)

    if not funcionario:
        flash("Funcionário não encontrado.", "error")
        return redirect(url_for("admin_dashboard"))

    if not security.can_access_record(current_user, funcionario):
        registrar_violacao_acesso(f"Movimentar funcionario_id={func_id}")
        flash("Acesso negado: servidor pertence a outra secretaria.", "error")
        return redirect(url_for("admin_dashboard", tab="dados"))

    if novo_local_id and not security.has_global_scope(current_user):
        loc_dest = db.session.get(LocalTrabalho, int(novo_local_id))
        if loc_dest and not security.can_access_record(current_user, loc_dest):
            registrar_violacao_acesso(f"Movimentar para local_id={novo_local_id} de outra secretaria")
            flash("Acesso negado: local de destino pertence a outra secretaria.", "error")
            return redirect(url_for("admin_dashboard", tab="dados"))

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
@security.require_permission("export_rh")
def importar_pdf_para_excel():

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
@security.require_permission("export_rh")
def importar_pdf():

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


@app.route("/gerar_rescisao_excluir/<int:id>", methods=["GET", "POST"])
@login_required
@security.require_permission("manage_rescisoes")
def gerar_rescisao_excluir(id):
    funcionario = db.session.get(Funcionario, id)
    if not funcionario:
        flash("Funcionário não encontrado", "error")
        return redirect(url_for("sistema"))
    if not security.can_access_record(current_user, funcionario):
        registrar_violacao_acesso(f"Rescisao rapida funcionario_id={id}")
        flash("Acesso negado: servidor pertence a outra secretaria.", "error")
        return redirect(url_for("sistema"))

    try:
        dt_sai = funcionario.dt_termino if funcionario.dt_termino else date.today()
        nova_rescisao = RescisaoHistorico(
            secretaria_id=funcionario.secretaria_id,
            nome=funcionario.nome,
            cpf=funcionario.cpf,
            rg=funcionario.rg,
            endereco=funcionario.endereco,
            funcao=funcionario.funcao.nome if funcionario.funcao else "N/A",
            num_contrato=funcionario.num_vinculo,
            data_inicio=funcionario.dt_inicio,
            data_saida=dt_sai,
        )
        db.session.add(nova_rescisao)

        dados_doc = {
            "nome": funcionario.nome,
            "funcao": funcionario.funcao.nome if funcionario.funcao else "N/A",
            "data_inicio": funcionario.dt_inicio,
            "data_saida": dt_sai,
            "cpf": funcionario.cpf,
            "rg": funcionario.rg,
            "endereco": funcionario.endereco,
            "num_contrato": funcionario.num_vinculo,
        }

        registrar_log("RESCISAO DE SERVIDOR", funcionario.nome, secretaria_id=funcionario.secretaria_id)

        funcionario.ativo = False
        if not funcionario.dt_termino:
            funcionario.dt_termino = dt_sai
        db.session.commit()

        fuso_br = pytz.timezone('America/Sao_Paulo')
        agora_br = datetime.now(fuso_br).replace(tzinfo=None)

        return render_template(
            "recisao_documento.html", f=dados_doc, data_atual=agora_br
        )

    except Exception as e:
        db.session.rollback()
        print(f"Erro ao processar rescisão: {e}")
        flash("Erro ao processar rescisão no banco de dados.", "error")
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
@security.require_permission("view_ponto")
def ponto_por_escola(local_id):
    escola = db.session.get(LocalTrabalho, local_id)
    if not escola or not security.can_access_record(current_user, escola):
        registrar_violacao_acesso(f"Ponto por unidade local_id={local_id}")
        flash("Acesso negado: unidade fora do seu escopo.", "error")
        return redirect(url_for(security.get_default_home_endpoint(current_user)))

    servidores = (
        security.scope_query(
            Funcionario.query.filter_by(local_trabalho_id=local_id),
            Funcionario,
            current_user,
        )
        .order_by(Funcionario.nome)
        .all()
    )

    mes_selecionado = request.args.get("mes", datetime.now().strftime("%Y-%m"))

    return render_template(
        "ponto_escola.html", escola=escola, servidores=servidores, mes=mes_selecionado
    )


@app.route("/admin/ponto/gerar_pdf/<int:func_id>")
@login_required
@security.require_permission("view_ponto")
def gerar_relatorio_frequencia(func_id):
    mes_ref = request.args.get("mes", datetime.now().strftime("%Y-%m"))
    ano, mes = map(int, mes_ref.split("-"))

    funcionario = db.session.get(Funcionario, func_id)
    if not funcionario:
        return "Servidor não encontrado", 404
    if not security.can_access_record(current_user, funcionario):
        registrar_violacao_acesso(f"Relatorio frequencia funcionario_id={func_id}")
        return "Acesso negado", 403
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

    # Busca atestados/justificativas aprovadas do servidor
    atestados_aprovados = JustificativaFalta.query.filter_by(
        funcionario_id=func_id,
        status="APROVADO"
    ).all()

    # Mapeia os dias com atestado aprovado
    dias_atestado = set()
    for just in atestados_aprovados:
        if just.data_inicio_afastamento:
            dias_lib = just.dias_liberados_municipio or just.dias_solicitados or 1
            for d_offset in range(dias_lib):
                dt_afast = just.data_inicio_afastamento + timedelta(days=d_offset)
                if dt_afast.year == ano and dt_afast.month == mes:
                    dias_atestado.add(dt_afast.day)

    # Gera a lista de todos os dias do mês para o relatório
    import calendar

    _, ultimo_dia = calendar.monthrange(ano, mes)

    dias_trabalhados = 0
    dias_faltosos = 0
    dias_abonados = 0
    folha_mensal = []

    for dia in range(1, ultimo_dia + 1):
        data_atual = date(ano, mes, dia)
        dia_semana = data_atual.weekday()  # 0=Segunda, 6=Domingo

        batidas = pontos_por_dia.get(dia, [])
        tem_atestado = dia in dias_atestado

        if batidas:
            status = "PRESENÇA"
        elif tem_atestado:
            status = "ATESTADO (ABONADO)"
        elif dia_semana < 5:
            status = "FALTA"
        else:
            status = "FINAL DE SEMANA"

        # Lógica de Faltas: Se for dia útil (seg a sex)
        if dia_semana < 5:
            if batidas:
                dias_trabalhados += 1
            elif tem_atestado:
                dias_abonados += 1
            else:
                dias_faltosos += 1

        folha_mensal.append(
            {
                "dia": data_atual.strftime("%d/%m/%Y"),
                "dia_nome": ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"][
                    dia_semana
                ],
                "batidas": batidas,
                "status": status,
            }
        )

    return render_template(
        "relatorio_frequencia_pdf.html",
        f=funcionario,
        folha=folha_mensal,
        resumo={
            "trabalhados": dias_trabalhados,
            "faltas": dias_faltosos,
            "abonados": dias_abonados,
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
@security.require_permission("manage_biometria", api=True)
def salvar_biometria():
    dados = request.json or {}
    funcionario_id = dados.get("id")
    foto_base64 = dados.get("foto")

    funcionario = db.session.get(Funcionario, funcionario_id)
    if funcionario:
        if not security.can_access_record(current_user, funcionario):
            registrar_violacao_acesso(f"Biometria funcionario_id={funcionario_id}")
            return {"error": "Não autorizado"}, 403
        funcionario.foto_biometria = foto_base64
        db.session.commit()
        registrar_log("MAPEAMENTO_FACIAL", funcionario.nome, secretaria_id=funcionario.secretaria_id)
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
@security.require_permission("view_rescisoes")
def reimprimir_rescisao(id):
    rescisao = db.session.get(RescisaoHistorico, id)
    if not rescisao:
        flash("Registro de rescisão não encontrado.", "error")
        return redirect(url_for("pagina_recisoes"))
    if not security.can_access_record(current_user, rescisao):
        registrar_violacao_acesso(f"Reimprimir rescisao_id={id}")
        flash("Acesso negado: registro pertence a outra secretaria.", "error")
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
@security.require_permission("manage_rescisoes", api=True)
def api_salvar_dados_rescisao():
    """Rota API para salvar as edições de histórico via AJAX sem recarregar a tela"""
    try:
        data = request.get_json() or {}
        rescisao_id = data.get("id")
        rescisao = db.session.get(RescisaoHistorico, rescisao_id)

        if not rescisao:
            return {"success": False, "message": "Registro não encontrado"}, 404
        if not security.can_access_record(current_user, rescisao):
            registrar_violacao_acesso(f"Editar rescisao_id={rescisao_id}")
            return {"success": False, "message": "Acesso negado: registro pertence a outra secretaria."}, 403

        rescisao.rg = data.get("rg")
        rescisao.endereco = data.get("endereco")
        rescisao.num_contrato = data.get("num_contrato")

        db.session.commit()
        registrar_log("ATUALIZOU DADOS HISTORICOS RESCISAO", rescisao.nome, secretaria_id=rescisao.secretaria_id)
        return {"success": True}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": str(e)}, 500
    
@app.route('/relatorio-geral')
@login_required
@security.require_permission("export_rh")
def relatorio_pessoal():
    funcionarios = security.scope_query(
        Funcionario.query.filter((Funcionario.ativo == True) | (Funcionario.ativo.is_(None))),
        Funcionario,
        current_user,
    ).order_by(Funcionario.nome).all()
    
    return render_template('relatorio_pessoal.html', funcionarios=funcionarios)    

@app.route("/admin/escolas/atalhos")
@login_required
@security.require_permission("view_ponto")
def atalhos_escolas():
    escolas = security.scope_query(
        LocalTrabalho.query, LocalTrabalho, current_user
    ).order_by(LocalTrabalho.nome).all()
    return render_template("atalhos_escolas.html", escolas=escolas)

@app.route("/admin/unidades_ponto")
@login_required
@security.require_permission("view_ponto")
def unidades_ponto():
    locais = security.scope_query(
        LocalTrabalho.query, LocalTrabalho, current_user
    ).order_by(LocalTrabalho.nome).all()
    return render_template("unidades_ponto.html", locais=locais)


# ==============================================================================
# MÓDULO INDEPENDENTE DE ORGANOGRAMA & QUADRO DE CARGOS DA SECRETARIA
# ==============================================================================

@app.route('/organograma')
@login_required
@security.require_permission("view_organograma")
def organograma_page():
    exercicios_q = security.scope_query(
        OrganogramaExercicio.query, OrganogramaExercicio, current_user
    )
    exercicios = exercicios_q.order_by(OrganogramaExercicio.ano.desc(), OrganogramaExercicio.id.desc()).all()

    if not exercicios and security.has_permission(current_user, "manage_organograma"):
        ano_atual = datetime.now().year
        sec_id_novo = current_user.secretaria_id
        sec_nome = current_user.secretaria.nome if current_user.secretaria else "SECRETARIA"
        sec_sigla = (current_user.secretaria.sigla if (current_user.secretaria and current_user.secretaria.sigla) else "GABINETE")
        novo_ex = OrganogramaExercicio(
            ano=ano_atual,
            titulo=f"Quadro de Cargos — {sec_nome} ({ano_atual})",
            secretaria_id=sec_id_novo,
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
            sigla=sec_sigla,
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
        cand = db.session.get(OrganogramaExercicio, exercicio_id)
        if cand and security.can_access_record(current_user, cand):
            selected_exercicio = cand
    if not selected_exercicio and exercicios:
        selected_exercicio = exercicios[0]

    return render_template('organograma.html',
                           exercicios=exercicios,
                           selected_exercicio=selected_exercicio)


@app.route('/api/organograma/tree/<int:exercicio_id>')
@login_required
@security.require_permission("view_organograma", api=True)
def api_organograma_tree(exercicio_id):
    exercicio = OrganogramaExercicio.query.get_or_404(exercicio_id)
    if not security.can_access_record(current_user, exercicio):
        registrar_violacao_acesso(f"Organograma tree exercicio_id={exercicio_id}")
        return {"success": False, "message": "Acesso negado: organograma pertence a outra secretaria."}, 403
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
@security.require_permission("manage_organograma", api=True)
def api_organograma_exercicio_salvar():
    try:
        data = request.json or {}
        ano = int(data.get('ano', datetime.now().year))
        titulo = data.get('titulo', f'Quadro de Cargos - Exercício {ano}').strip()
        copiar_de_id = data.get('copiar_de_id')
        sec_id = (
            data.get('secretaria_id') or current_user.secretaria_id
            if security.has_global_scope(current_user)
            else current_user.secretaria_id
        )

        novo_ex = OrganogramaExercicio(
            ano=ano,
            titulo=titulo,
            secretaria_id=int(sec_id) if sec_id else None,
            ativo=True,
            criado_por_id=current_user.id
        )
        db.session.add(novo_ex)
        db.session.commit()

        if copiar_de_id:
            ex_antigo = db.session.get(OrganogramaExercicio, copiar_de_id)
            if ex_antigo and security.can_access_record(current_user, ex_antigo):
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
                        new_node = db.session.get(OrganogramaNode, new_node_id)
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
@security.require_permission("manage_organograma", api=True)
def api_organograma_exercicio_limpar():
    try:
        data = request.json or {}
        exercicio_id = data.get('exercicio_id')
        if not exercicio_id:
            return {"success": False, "message": "ID do exercício é obrigatório."}, 400

        ex_obj = db.session.get(OrganogramaExercicio, exercicio_id)
        if not ex_obj or not security.can_access_record(current_user, ex_obj):
            registrar_violacao_acesso(f"Limpar organograma exercicio_id={exercicio_id}")
            return {"success": False, "message": "Acesso negado: organograma pertence a outra secretaria."}, 403

        OrganogramaHistorico.query.filter_by(exercicio_id=exercicio_id).delete(synchronize_session=False)

        OrganogramaServidor.query.filter(OrganogramaServidor.node_id.in_(
            db.session.query(OrganogramaNode.id).filter_by(exercicio_id=exercicio_id)
        )).delete(synchronize_session=False)

        OrganogramaNode.query.filter_by(exercicio_id=exercicio_id).delete(synchronize_session=False)
        db.session.commit()

        sec_sigla = (ex_obj.secretaria.sigla if (ex_obj.secretaria and ex_obj.secretaria.sigla) else "GABINETE")
        no_raiz = OrganogramaNode(
            exercicio_id=exercicio_id,
            parent_id=None,
            tipo="CARGO_CHEFIA",
            titulo="Secretário(a) Municipal",
            sigla=sec_sigla,
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
@security.require_permission("manage_organograma", api=True)
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

        if node_id:
            node_chk = db.session.get(OrganogramaNode, node_id)
            if not node_chk or not security.can_access_record(current_user, node_chk):
                registrar_violacao_acesso(f"Salvar organograma node_id={node_id}")
                return {"success": False, "message": "Acesso negado."}, 403
        elif exercicio_id:
            ex_chk = db.session.get(OrganogramaExercicio, exercicio_id)
            if not ex_chk or not security.can_access_record(current_user, ex_chk):
                registrar_violacao_acesso(f"Adicionar node em exercicio_id={exercicio_id}")
                return {"success": False, "message": "Acesso negado."}, 403
            
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
@security.require_permission("manage_organograma", api=True)
def api_organograma_node_deletar():
    try:
        data = request.json or {}
        node_id = data.get('node_id')
        node = OrganogramaNode.query.get_or_404(node_id)
        if not security.can_access_record(current_user, node):
            registrar_violacao_acesso(f"Deletar organograma node_id={node_id}")
            return {"success": False, "message": "Acesso negado."}, 403
        
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
@security.require_permission("manage_organograma", api=True)
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
        if not security.can_access_record(current_user, node):
            registrar_violacao_acesso(f"Nomear em organograma node_id={node_id}")
            return {"success": False, "message": "Acesso negado."}, 403
        
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
@security.require_permission("manage_organograma", api=True)
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
        node = db.session.get(OrganogramaNode, servidor.node_id)
        if not node or not security.can_access_record(current_user, node):
            registrar_violacao_acesso(f"Exonerar organograma servidor_id={servidor_id}")
            return {"success": False, "message": "Acesso negado."}, 403
        
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
@security.require_permission("manage_organograma", api=True)
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
        if not security.can_access_record(current_user, node):
            registrar_violacao_acesso(f"Substituir organograma servidor_id={servidor_antigo_id}")
            return {"success": False, "message": "Acesso negado."}, 403
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
@security.require_permission("view_organograma")
def organograma_exportar_excel(exercicio_id):
    exercicio = OrganogramaExercicio.query.get_or_404(exercicio_id)
    if not security.can_access_record(current_user, exercicio):
        registrar_violacao_acesso(f"Exportar organograma exercicio_id={exercicio_id}")
        return "Acesso negado", 403
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
@security.require_permission("view_organograma", api=True)
def api_organograma_buscar_funcionarios():
    q = request.args.get('q', '').strip()
    query = security.scope_query(Funcionario.query, Funcionario, current_user)
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
@security.require_permission("view_organograma")
def organograma_pdf_view(exercicio_id):
    exercicio = OrganogramaExercicio.query.get_or_404(exercicio_id)
    if not security.can_access_record(current_user, exercicio):
        registrar_violacao_acesso(f"PDF organograma exercicio_id={exercicio_id}")
        return "Acesso negado", 403
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
        ip_key = f"portal_srv:{request.remote_addr}"
        limited, retry_after = security.login_rate_limiter.is_limited(ip_key, max_attempts=15, window_seconds=300)
        if limited:
            flash(f"Muitas tentativas de acesso. Aguarde {retry_after} segundos.", "danger")
            return redirect(url_for("portal_servidor_login"))

        cpf_raw = request.form.get("cpf", "").strip()
        data_nasc_raw = request.form.get("data_nasc", "").strip()

        cpf_clean = re.sub(r"\D", "", cpf_raw)
        if not cpf_clean:
            flash("Informe um CPF válido para login.", "danger")
            return redirect(url_for("portal_servidor_login"))

        # Busca indexada por cpf_limpo (sem carregar todos os registros na memória!)
        funcionario = Funcionario.query.filter(
            (Funcionario.cpf_limpo == cpf_clean) | (Funcionario.cpf == cpf_raw)
        ).order_by(Funcionario.ativo.desc(), Funcionario.id.desc()).first()

        if not funcionario:
            security.login_rate_limiter.register_failure(ip_key)
            flash("CPF não encontrado no cadastro do município. Procure o RH da Secretaria.", "danger")
            return redirect(url_for("portal_servidor_login"))

        if not funcionario.data_nasc:
            flash("Data de nascimento não cadastrada para este servidor. Contate o RH.", "danger")
            return redirect(url_for("portal_servidor_login"))

        dt_nasc_valida = False
        data_nasc_clean = re.sub(r"\D", "", data_nasc_raw)

        dt_func_str1 = funcionario.data_nasc.strftime("%d/%m/%Y")
        dt_func_str2 = funcionario.data_nasc.strftime("%Y-%m-%d")
        dt_func_clean = funcionario.data_nasc.strftime("%d%m%Y")

        if data_nasc_raw in (dt_func_str1, dt_func_str2) or data_nasc_clean == dt_func_clean:
            dt_nasc_valida = True

        if not dt_nasc_valida:
            security.login_rate_limiter.register_failure(ip_key)
            flash("Data de nascimento (senha) incorreta. Tente no formato DD/MM/AAAA.", "danger")
            return redirect(url_for("portal_servidor_login"))

        security.login_rate_limiter.reset(ip_key)
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

    is_owner = session.get("servidor_id") == just.funcionario_id
    is_rh = (
        current_user.is_authenticated
        and security.has_permission(current_user, "view_atestados")
        and security.can_access_record(current_user, just)
    )

    if not (is_owner or is_rh):
        if current_user.is_authenticated:
            registrar_violacao_acesso(f"Download atestado_id={id}")
            return "Acesso negado", 403
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
@security.require_permission("view_atestados")
def admin_atestados():
    status_filter = request.args.get("status", "TODOS").upper()
    search = request.args.get("search", "").strip()

    query = security.scope_query(JustificativaFalta.query, JustificativaFalta, current_user)
    if security.get_role_scope(current_user) == "unidade":
        query = query.join(Funcionario).filter(Funcionario.local_trabalho_id == current_user.local_trabalho_id)

    if status_filter in ("PENDENTE", "APROVADO", "REJEITADO"):
        query = query.filter(JustificativaFalta.status == status_filter)

    if search:
        search_like = f"%{search}%"
        if security.get_role_scope(current_user) != "unidade":
            query = query.join(Funcionario)
        query = query.filter(
            (Funcionario.nome.ilike(search_like)) |
            (Funcionario.cpf.ilike(search_like)) |
            (JustificativaFalta.protocolo.ilike(search_like))
        )

    justificativas = query.order_by(JustificativaFalta.data_solicitacao.desc()).all()

    base_query = security.scope_query(JustificativaFalta.query, JustificativaFalta, current_user)
    if security.get_role_scope(current_user) == "unidade":
        base_query = base_query.join(Funcionario).filter(Funcionario.local_trabalho_id == current_user.local_trabalho_id)

    total_qtd = base_query.count()
    pendentes_qtd = base_query.filter(JustificativaFalta.status == "PENDENTE").count()
    aprovados_qtd = base_query.filter(JustificativaFalta.status == "APROVADO").count()
    rejeitados_qtd = base_query.filter(JustificativaFalta.status == "REJEITADO").count()

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
@security.require_permission("decide_atestados", api=True)
def api_atestados_aprovar():
    data = request.get_json() or {}
    just_id = data.get("id")
    dias_liberados = data.get("dias_liberados", 1)
    obs = data.get("observacao", "").strip()

    if not just_id:
        return jsonify({"success": False, "message": "ID do atestado não fornecido."})

    just = db.session.get(JustificativaFalta, just_id)
    if not just:
        return jsonify({"success": False, "message": "Solicitação não encontrada."})
    if not security.can_access_record(current_user, just):
        registrar_violacao_acesso(f"Aprovar atestado_id={just_id}")
        return jsonify({"success": False, "message": "Acesso negado: atestado pertence a outra secretaria."}), 403

    try:
        dias_val = int(dias_liberados)
    except ValueError:
        dias_val = just.dias_solicitados

    just.status = "APROVADO"
    just.dias_liberados_municipio = dias_val
    just.observacao_rh = obs
    just.analisado_por_id = current_user.id
    just.data_analise = datetime.utcnow()

    log = LogAuditoria(
        usuario_id=current_user.id,
        secretaria_id=just.secretaria_id,
        nivel="INFO",
        acao=f"Aprovou Atestado {just.protocolo}"[:250],
        alvo=f"Servidor: {just.funcionario.nome} | Dias: {dias_val}"[:495]
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({"success": True, "message": "Solicitação Aprovada com Sucesso!"})


@app.route("/api/atestados/reprovar", methods=["POST"])
@login_required
@security.require_permission("decide_atestados", api=True)
def api_atestados_reprovar():
    data = request.get_json() or {}
    just_id = data.get("id")
    motivo = data.get("motivo_rejeicao", "").strip()

    if not just_id:
        return jsonify({"success": False, "message": "ID do atestado não fornecido."})

    if not motivo:
        return jsonify({"success": False, "message": "O motivo do indeferimento é OBRIGATÓRIO!"})

    just = db.session.get(JustificativaFalta, just_id)
    if not just:
        return jsonify({"success": False, "message": "Solicitação não encontrada."})
    if not security.can_access_record(current_user, just):
        registrar_violacao_acesso(f"Reprovar atestado_id={just_id}")
        return jsonify({"success": False, "message": "Acesso negado: atestado pertence a outra secretaria."}), 403

    just.status = "REJEITADO"
    just.motivo_rejeicao = motivo
    just.analisado_por_id = current_user.id
    just.data_analise = datetime.utcnow()

    log = LogAuditoria(
        usuario_id=current_user.id,
        secretaria_id=just.secretaria_id,
        nivel="INFO",
        acao=f"Indeferiu Atestado {just.protocolo}"[:250],
        alvo=f"Servidor: {just.funcionario.nome} | Motivo: {motivo}"[:495]
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({"success": True, "message": "Solicitação Indeferida com Sucesso!"})


@app.route("/admin/atestados/pdf/<int:id>")
def atestado_parecer_pdf(id):
    just = JustificativaFalta.query.get_or_404(id)

    servidor_id = session.get("servidor_id")
    is_owner = servidor_id == just.funcionario_id
    is_rh = (
        current_user.is_authenticated
        and security.has_permission(current_user, "view_atestados")
        and security.can_access_record(current_user, just)
    )
    if not (is_owner or is_rh):
        if current_user.is_authenticated:
            registrar_violacao_acesso(f"PDF parecer atestado_id={id}")
            return "Acesso negado", 403
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for("portal_servidor_login"))

    data_emissao = datetime.now().strftime("%d/%m/%Y às %H:%M")

    return render_template(
        "atestado_parecer_pdf.html",
        j=just,
        data_emissao=data_emissao
    )


# ==========================================
def obter_servidores_pendentes(funcionarios, locais):
    """
    Retorna os IDs e a lista estruturada com o diagnóstico dos servidores que possuem pendências eleitorais:
    - Zona Eleitoral em branco
    - Zona Eleitoral diferente da Zona 18 ('018' ou '18')
    - Seção Eleitoral em branco
    - Seção e Zona que não coincidem com nenhum Colégio Eleitoral cadastrado no sistema
    """
    mapeados_ids = set()

    for loc in locais:
        sec_norm_set = loc.get_secoes_normalized()
        loc_zona_norm = normalizar_numero_eleitoral(loc.zona_eleitoral)

        for f in funcionarios:
            f_zona_norm = normalizar_numero_eleitoral(f.zona_eleitoral)
            f_sec_norm = normalizar_numero_eleitoral(f.secao_eleitoral)

            zona_matches = (not f_zona_norm or f_zona_norm in ["18", "018", loc_zona_norm])
            if zona_matches and f_sec_norm and f_sec_norm in sec_norm_set:
                mapeados_ids.add(f.id)

    pendentes_dados = []
    pendentes_ids = set()

    for f in funcionarios:
        f_zona_norm = normalizar_numero_eleitoral(f.zona_eleitoral)
        f_sec_norm = normalizar_numero_eleitoral(f.secao_eleitoral)

        sem_zona = not f_zona_norm
        fora_zona18 = bool(f_zona_norm and f_zona_norm not in ["18", "018"])
        sem_secao = not f_sec_norm
        nao_mapeado = f.id not in mapeados_ids

        if sem_zona or fora_zona18 or sem_secao or nao_mapeado:
            pendentes_ids.add(f.id)
            motivos = []

            if sem_zona:
                motivos.append("Zona em branco")
            elif fora_zona18:
                motivos.append(f"Zona {f.zona_eleitoral} (Fora da Zona 18)")

            if sem_secao:
                motivos.append("Seção em branco")
            elif nao_mapeado:
                motivos.append("Seção/Zona diferente do cadastro dos colégios")

            pendentes_dados.append({
                "funcionario": f,
                "motivo": " | ".join(motivos) if motivos else "Pendência Cadastral"
            })

    return pendentes_ids, pendentes_dados


@app.route("/eleitoral", methods=["GET"])
@login_required
@security.require_permission("view_eleitoral")
def eleitoral_index():
    sec_id = request.args.get("secretaria_id", type=int)
    busca = request.args.get("busca", "").strip()

    secretarias = Secretaria.query.order_by(Secretaria.nome).all()
    locais = LocalVotacao.query.order_by(LocalVotacao.nome).all()

    query_func = Funcionario.query.filter_by(ativo=True)
    if sec_id:
        query_func = query_func.filter_by(secretaria_id=sec_id)
    
    funcionarios = query_func.all()

    locais_dados = []
    mapeados_ids = set()

    for loc in locais:
        if busca and busca.lower() not in loc.nome.lower() and busca.lower() not in (loc.bairro or "").lower() and busca not in loc.secoes:
            continue

        sec_norm_set = loc.get_secoes_normalized()
        loc_zona_norm = normalizar_numero_eleitoral(loc.zona_eleitoral)

        funcs_no_local = []
        for f in funcionarios:
            f_zona_norm = normalizar_numero_eleitoral(f.zona_eleitoral)
            f_sec_norm = normalizar_numero_eleitoral(f.secao_eleitoral)

            zona_matches = (not f_zona_norm or f_zona_norm in ["18", "018", loc_zona_norm])
            if zona_matches and f_sec_norm and f_sec_norm in sec_norm_set:
                funcs_no_local.append(f)
                mapeados_ids.add(f.id)

        por_secretaria = {}
        for f in funcs_no_local:
            sec_nome = f.secretaria.nome if f.secretaria else "Sem Secretaria"
            por_secretaria[sec_nome] = por_secretaria.get(sec_nome, 0) + 1

        locais_dados.append({
            "local": loc,
            "total_servidores": len(funcs_no_local),
            "por_secretaria": por_secretaria,
            "secoes_lista": loc.get_secoes_list()
        })

    total_servidores = len(funcionarios)
    total_com_titulo = sum(1 for f in funcionarios if f.titulo_eleitor or f.secao_eleitoral)
    total_mapeados = len(mapeados_ids)
    
    # Pendências eleitorais calculadas via função unificada
    pendentes_ids, _ = obter_servidores_pendentes(funcionarios, locais)
    total_pendentes = len(pendentes_ids)

    top_locais = sorted(locais_dados, key=lambda x: x["total_servidores"], reverse=True)[:5]

    return render_template(
        "locais_votacao.html",
        locais_dados=locais_dados,
        secretarias=secretarias,
        sec_id_selecionado=sec_id,
        busca=busca,
        stats={
            "total_servidores": total_servidores,
            "total_com_titulo": total_com_titulo,
            "total_mapeados": total_mapeados,
            "total_pendentes": total_pendentes,
            "total_locais": len(locais),
            "top_locais": top_locais
        }
    )


@app.route("/eleitoral/local/novo", methods=["POST"])
@login_required
@security.require_permission("manage_eleitoral")
def eleitoral_local_novo():
    nome = request.form.get("nome", "").strip()
    zona_eleitoral = request.form.get("zona_eleitoral", "018").strip()
    secoes = request.form.get("secoes", "").strip()
    bairro = request.form.get("bairro", "").strip()
    endereco = request.form.get("endereco", "").strip()
    observacoes = request.form.get("observacoes", "").strip()

    if not nome or not secoes:
        flash("Nome do Colégio e Seções são obrigatórios!", "danger")
        return redirect(url_for("eleitoral_index"))

    novo_local = LocalVotacao(
        nome=nome,
        zona_eleitoral=zona_eleitoral,
        secoes=secoes,
        bairro=bairro,
        endereco=endereco,
        observacoes=observacoes
    )
    db.session.add(novo_local)

    log = LogAuditoria(
        usuario_id=current_user.id,
        acao="Cadastrou Local de Votação"[:50],
        alvo=f"Local: {nome} | Z: {zona_eleitoral} | Seções: {secoes}"[:250]
    )
    db.session.add(log)
    db.session.commit()

    flash(f"Local de Votação '{nome}' cadastrado com sucesso!", "success")
    return redirect(url_for("eleitoral_index"))


@app.route("/eleitoral/local/<int:id>/editar", methods=["POST"])
@login_required
@security.require_permission("manage_eleitoral")
def eleitoral_local_editar(id):
    local = LocalVotacao.query.get_or_404(id)

    local.nome = request.form.get("nome", local.nome).strip()
    local.zona_eleitoral = request.form.get("zona_eleitoral", local.zona_eleitoral).strip()
    local.secoes = request.form.get("secoes", local.secoes).strip()
    local.bairro = request.form.get("bairro", local.bairro).strip()
    local.endereco = request.form.get("endereco", local.endereco).strip()
    local.observacoes = request.form.get("observacoes", local.observacoes).strip()

    log = LogAuditoria(
        usuario_id=current_user.id,
        acao=f"Editou Local Votação ID {id}"[:50],
        alvo=f"Local: {local.nome} | Seções: {local.secoes}"[:250]
    )
    db.session.add(log)
    db.session.commit()

    flash(f"Local de Votação '{local.nome}' atualizado!", "success")
    return redirect(url_for("eleitoral_index"))


@app.route("/eleitoral/local/<int:id>/excluir", methods=["POST"])
@login_required
@security.require_permission("manage_eleitoral")
def eleitoral_local_excluir(id):
    local = LocalVotacao.query.get_or_404(id)
    nome = local.nome

    db.session.delete(local)
    log = LogAuditoria(
        usuario_id=current_user.id,
        acao=f"Excluiu Local Votação ID {id}"[:50],
        alvo=f"Local Excluído: {nome}"[:250]
    )
    db.session.add(log)
    db.session.commit()

    flash(f"Local de Votação '{nome}' excluído com sucesso.", "warning")
    return redirect(url_for("eleitoral_index"))


@app.route("/api/eleitoral/local/<int:id>/servidores", methods=["GET"])
@login_required
@security.require_permission("view_eleitoral", api=True)
def api_eleitoral_servidores_local(id):
    local = LocalVotacao.query.get_or_404(id)
    sec_id = request.args.get("secretaria_id", type=int)

    sec_norm_set = local.get_secoes_normalized()
    loc_zona_norm = normalizar_numero_eleitoral(local.zona_eleitoral)

    query = Funcionario.query.filter_by(ativo=True)
    if sec_id:
        query = query.filter_by(secretaria_id=sec_id)

    funcionarios = query.all()
    resultado = []

    for f in funcionarios:
        f_zona_norm = normalizar_numero_eleitoral(f.zona_eleitoral)
        f_sec_norm = normalizar_numero_eleitoral(f.secao_eleitoral)

        zona_matches = (not f_zona_norm or f_zona_norm in ["18", "018", loc_zona_norm])
        if zona_matches and f_sec_norm and f_sec_norm in sec_norm_set:
            resultado.append({
                "id": f.id,
                "nome": f.nome,
                "cpf": f.cpf or "---",
                "funcao": f.funcao.nome if f.funcao else "---",
                "secretaria": f.secretaria.nome if f.secretaria else "---",
                "local_trabalho": f.local_trabalho.nome if f.local_trabalho else "---",
                "zona": f.zona_eleitoral or local.zona_eleitoral,
                "secao": f.secao_eleitoral or "---",
                "telefone": f.telefone or "---"
            })

    resultado.sort(key=lambda x: x["nome"])

    return jsonify({
        "success": True,
        "local": {
            "id": local.id,
            "nome": local.nome,
            "zona": local.zona_eleitoral,
            "secoes": local.secoes,
            "bairro": local.bairro or "---",
            "endereco": local.endereco or "---"
        },
        "total": len(resultado),
        "servidores": resultado
    })


@app.route("/api/eleitoral/servidores-pendentes", methods=["GET"])
@login_required
@security.require_permission("view_eleitoral", api=True)
def api_eleitoral_servidores_pendentes():
    sec_id = request.args.get("secretaria_id", type=int)

    locais = LocalVotacao.query.all()
    query = Funcionario.query.filter_by(ativo=True)
    if sec_id:
        query = query.filter_by(secretaria_id=sec_id)
    
    funcionarios = query.all()
    _, pendentes_dados = obter_servidores_pendentes(funcionarios, locais)

    resultado = []
    for item in pendentes_dados:
        f = item["funcionario"]
        resultado.append({
            "id": f.id,
            "nome": f.nome,
            "cpf": f.cpf or "---",
            "funcao": f.funcao.nome if f.funcao else "---",
            "secretaria": f.secretaria.nome if f.secretaria else "---",
            "local_trabalho": f.local_trabalho.nome if f.local_trabalho else "---",
            "zona": f.zona_eleitoral or "---",
            "secao": f.secao_eleitoral or "---",
            "telefone": f.telefone or "---",
            "motivo": item["motivo"]
        })

    resultado.sort(key=lambda x: x["nome"])

    return jsonify({
        "success": True,
        "total": len(resultado),
        "servidores": resultado
    })


@app.route("/eleitoral/pdf", methods=["GET"])
@login_required
@security.require_permission("view_eleitoral")
def eleitoral_pdf():
    tipo = request.args.get("tipo", "sintetico")
    sec_id = request.args.get("secretaria_id", type=int)
    local_id = request.args.get("local_id", type=int)
    secao_filtro = request.args.get("secao", "").strip()
    pendentes_flag = request.args.get("pendentes", type=int) or (1 if tipo == "pendentes" else 0)

    sec_selecionada = Secretaria.query.get(sec_id) if sec_id else None
    local_selecionado = LocalVotacao.query.get(local_id) if local_id else None

    query_func = Funcionario.query.filter_by(ativo=True)
    if sec_id:
        query_func = query_func.filter_by(secretaria_id=sec_id)
    funcionarios = query_func.all()

    locais_all = LocalVotacao.query.order_by(LocalVotacao.nome).all()

    if pendentes_flag:
        _, pendentes_dados = obter_servidores_pendentes(funcionarios, locais_all)
        servidores_pendentes = [item["funcionario"] for item in pendentes_dados]
        servidores_pendentes.sort(key=lambda x: (x.secretaria.nome if x.secretaria else "", x.nome))
        data_emissao = datetime.now().strftime("%d/%m/%Y às %H:%M")

        return render_template(
            "locais_votacao_pdf.html",
            tipo="pendentes",
            servidores_pendentes=servidores_pendentes,
            sec_selecionada=sec_selecionada,
            total_geral_eleitores=len(servidores_pendentes),
            data_emissao=data_emissao
        )

    if local_id:
        locais = LocalVotacao.query.filter_by(id=local_id).all()
    else:
        locais = locais_all

    secao_norm_filtro = normalizar_numero_eleitoral(secao_filtro) if secao_filtro else None

    relatorio_dados = []
    total_geral_eleitores = 0

    for loc in locais:
        sec_norm_set = loc.get_secoes_normalized()
        loc_zona_norm = normalizar_numero_eleitoral(loc.zona_eleitoral)

        funcs_no_local = []
        for f in funcionarios:
            f_zona_norm = normalizar_numero_eleitoral(f.zona_eleitoral)
            f_sec_norm = normalizar_numero_eleitoral(f.secao_eleitoral)

            zona_matches = (not f_zona_norm or f_zona_norm == loc_zona_norm)
            if zona_matches and f_sec_norm and f_sec_norm in sec_norm_set:
                if secao_norm_filtro and f_sec_norm != secao_norm_filtro:
                    continue
                funcs_no_local.append(f)

        if not funcs_no_local and secao_norm_filtro:
            continue

        funcs_no_local.sort(key=lambda x: (x.secao_eleitoral or "", x.nome))

        por_secretaria = {}
        for f in funcs_no_local:
            snome = f.secretaria.nome if f.secretaria else "Sem Secretaria"
            por_secretaria[snome] = por_secretaria.get(snome, 0) + 1

        total_geral_eleitores += len(funcs_no_local)

        relatorio_dados.append({
            "local": loc,
            "total_servidores": len(funcs_no_local),
            "por_secretaria": por_secretaria,
            "servidores": funcs_no_local
        })

    data_emissao = datetime.now().strftime("%d/%m/%Y às %H:%M")

    return render_template(
        "locais_votacao_pdf.html",
        tipo=tipo,
        locais_dados=relatorio_dados,
        sec_selecionada=sec_selecionada,
        local_selecionado=local_selecionado,
        secao_filtro=secao_filtro,
        total_geral_eleitores=total_geral_eleitores,
        data_emissao=data_emissao
    )


# ==============================================================================
# MÓDULO COMPLETO DE BACKUP & RESTAURAÇÃO (FULL SYSTEM ENCRYPTED SNAPSHOT)
# ==============================================================================

def _is_backup_admin():
    return security.has_permission(current_user, "manage_backup")


def _get_backup_csrf_token():
    return security.get_csrf_token()


def _validate_backup_csrf():
    return security.validate_csrf_request()


def _formatar_tamanho(num_bytes):
    try:
        n = float(num_bytes or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024.0 or unit == "GB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.2f} GB"


@app.route("/admin/backup", methods=["GET"])
@login_required
def admin_backup():
    if not _is_backup_admin():
        flash("Acesso negado: Apenas administradores podem acessar o Módulo de Backup e Restauração.", "error")
        return redirect(url_for("sistema"))

    inventario = backup_service.get_system_inventory(db, app.root_path)
    bkp_dir = backup_service.get_backup_dir(app.root_path)

    historico_db = (
        BackupHistorico.query.order_by(BackupHistorico.data_hora.desc())
        .limit(50)
        .all()
    )

    fuso_br = pytz.timezone("America/Sao_Paulo")
    historico_lista = []
    ultimo_backup_ok = None

    for item in historico_db:
        caminho = os.path.join(bkp_dir, os.path.basename(item.nome_arquivo))
        disponivel = os.path.isfile(caminho)
        dt_br = (
            pytz.utc.localize(item.data_hora).astimezone(fuso_br)
            if item.data_hora
            else None
        )
        entry = {
            "id": item.id,
            "nome_arquivo": item.nome_arquivo,
            "tipo": item.tipo,
            "status": item.status,
            "tamanho_bytes": item.tamanho_bytes or 0,
            "tamanho_fmt": _formatar_tamanho(item.tamanho_bytes),
            "sha256": item.sha256 or "",
            "total_tabelas": item.total_tabelas or 0,
            "total_registros": item.total_registros or 0,
            "total_arquivos": item.total_arquivos or 0,
            "origem_banco": item.origem_banco or "",
            "observacao": item.observacao or "",
            "criado_por_nome": item.criado_por_nome or "Sistema",
            "ip_origem": item.ip_origem or "",
            "data_hora_fmt": dt_br.strftime("%d/%m/%Y às %H:%M:%S") if dt_br else "---",
            "disponivel": disponivel,
        }
        historico_lista.append(entry)
        if ultimo_backup_ok is None and item.tipo in ("MANUAL", "PRE_RESTORE") and item.status == "CONCLUIDO":
            ultimo_backup_ok = {
                "data_hora_fmt": entry["data_hora_fmt"],
                "dias_atras": (datetime.utcnow() - item.data_hora).days if item.data_hora else 999,
                "nome_arquivo": item.nome_arquivo,
            }

    return render_template(
        "admin_backup.html",
        inventario=inventario,
        total_media_fmt=_formatar_tamanho(inventario["total_media_bytes"]),
        historico=historico_lista,
        ultimo_backup_ok=ultimo_backup_ok,
        csrf_token=_get_backup_csrf_token(),
        role=current_user.role,
        is_admin=current_user.is_admin,
    )


@app.route("/api/backup/gerar", methods=["POST"])
@login_required
def api_backup_gerar():
    if not _is_backup_admin():
        return jsonify({"success": False, "message": "Acesso não autorizado."}), 403
    if not _validate_backup_csrf():
        return jsonify({"success": False, "message": "Token de segurança inválido. Recarregue a página."}), 400

    data = request.get_json(silent=True) or request.form
    senha_backup = (data.get("backup_password") or "").strip()
    confirmar_senha = (data.get("backup_password_confirm") or "").strip()
    observacao = (data.get("observacao") or "").strip()[:300]

    if len(senha_backup) < 8:
        return jsonify({"success": False, "message": "A senha de criptografia do backup deve ter no mínimo 8 caracteres."}), 400
    if senha_backup != confirmar_senha:
        return jsonify({"success": False, "message": "As senhas do backup não coincidem."}), 400

    try:
        resultado = backup_service.create_full_backup(
            db=db,
            app_root=app.root_path,
            password=senha_backup,
            created_by=current_user.username,
            prefix="gestoor360_full",
            observacao=observacao,
        )
        manifest = resultado["manifest"]
        totals = manifest["totals"]

        registro = BackupHistorico(
            nome_arquivo=resultado["filename"],
            tipo="MANUAL",
            status="CONCLUIDO",
            tamanho_bytes=resultado["size_bytes"],
            sha256=resultado["sha256"],
            total_tabelas=totals["tables"],
            total_registros=totals["records"],
            total_arquivos=totals["media_files"],
            origem_banco=manifest["source_dialect"],
            observacao=observacao or "Backup completo sob demanda",
            criado_por_id=current_user.id,
            criado_por_nome=current_user.username,
            ip_origem=request.remote_addr,
            data_hora=datetime.utcnow(),
        )
        db.session.add(registro)
        db.session.commit()

        registrar_log(
            "GEROU BACKUP COMPLETO",
            f"{resultado['filename']} ({totals['records']} registros, {totals['media_files']} mídias, {_formatar_tamanho(resultado['size_bytes'])})",
        )

        return jsonify(
            {
                "success": True,
                "message": "Backup completo gerado e criptografado com sucesso!",
                "backup": {
                    "id": registro.id,
                    "filename": resultado["filename"],
                    "size_bytes": resultado["size_bytes"],
                    "size_fmt": _formatar_tamanho(resultado["size_bytes"]),
                    "sha256": resultado["sha256"],
                    "totals": totals,
                    "download_url": url_for("admin_backup_download", backup_id=registro.id),
                },
            }
        )
    except backup_service.BackupError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Erro ao gerar backup: {str(e)}"}), 500


@app.route("/admin/backup/download/<int:backup_id>", methods=["GET"])
@login_required
def admin_backup_download(backup_id):
    if not _is_backup_admin():
        flash("Acesso não autorizado.", "error")
        return redirect(url_for("sistema"))

    registro = db.session.get(BackupHistorico, backup_id)
    if not registro:
        flash("Registro de backup não encontrado.", "error")
        return redirect(url_for("admin_backup"))

    safe_name = os.path.basename(registro.nome_arquivo)
    caminho = os.path.join(backup_service.get_backup_dir(app.root_path), safe_name)
    if not os.path.isfile(caminho):
        flash("O arquivo físico deste backup não está mais disponível no servidor (apenas registro histórico).", "error")
        return redirect(url_for("admin_backup"))

    registrar_log("BAIXOU BACKUP COMPLETO", f"{safe_name} (ID #{backup_id})")
    return send_file(
        caminho,
        as_attachment=True,
        download_name=safe_name,
        mimetype="application/octet-stream",
    )


@app.route("/api/backup/verificar/<int:backup_id>", methods=["POST"])
@login_required
def api_backup_verificar(backup_id):
    if not _is_backup_admin():
        return jsonify({"success": False, "message": "Acesso não autorizado."}), 403
    if not _validate_backup_csrf():
        return jsonify({"success": False, "message": "Token de segurança inválido. Recarregue a página."}), 400

    registro = db.session.get(BackupHistorico, backup_id)
    if not registro:
        return jsonify({"success": False, "message": "Backup não encontrado."}), 404

    safe_name = os.path.basename(registro.nome_arquivo)
    caminho = os.path.join(backup_service.get_backup_dir(app.root_path), safe_name)
    if not os.path.isfile(caminho):
        return jsonify({"success": False, "message": "Arquivo físico não encontrado no servidor."}), 404

    data = request.get_json(silent=True) or request.form
    senha_backup = (data.get("backup_password") or "").strip()

    try:
        with open(caminho, "rb") as f_in:
            enc_bytes = f_in.read()
        preview, _ = backup_service.inspect_backup_bytes(db, enc_bytes, senha_backup)
        return jsonify(
            {
                "success": True,
                "message": "Integridade 100% verificada! Todas as tabelas e arquivos passaram na validação AES-256-GCM e SHA-256.",
                "totals": preview["manifest"]["totals"],
                "created_at_br": preview["manifest"]["created_at_br"],
                "sha256": preview["sha256"],
            }
        )
    except backup_service.BackupError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro ao verificar integridade: {str(e)}"}), 500


@app.route("/api/backup/excluir/<int:backup_id>", methods=["POST"])
@login_required
def api_backup_excluir(backup_id):
    if not _is_backup_admin():
        return jsonify({"success": False, "message": "Acesso não autorizado."}), 403
    if not _validate_backup_csrf():
        return jsonify({"success": False, "message": "Token de segurança inválido. Recarregue a página."}), 400

    data = request.get_json(silent=True) or request.form
    admin_password = data.get("admin_password") or ""
    if not current_user.check_password(admin_password):
        return jsonify({"success": False, "message": "Senha do administrador incorreta."}), 403

    registro = db.session.get(BackupHistorico, backup_id)
    if not registro:
        return jsonify({"success": False, "message": "Backup não encontrado."}), 404

    safe_name = os.path.basename(registro.nome_arquivo)
    caminho = os.path.join(backup_service.get_backup_dir(app.root_path), safe_name)
    try:
        if os.path.isfile(caminho):
            os.remove(caminho)
        registro.status = "ARQUIVO_REMOVIDO"
        db.session.commit()
        registrar_log("REMOVEU ARQUIVO DE BACKUP", f"{safe_name} (ID #{backup_id})")
        return jsonify({"success": True, "message": "Arquivo de backup removido do disco do servidor com sucesso."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Erro ao remover arquivo: {str(e)}"}), 500


@app.route("/api/backup/inspecionar", methods=["POST"])
@login_required
def api_backup_inspecionar():
    if not _is_backup_admin():
        return jsonify({"success": False, "message": "Acesso não autorizado."}), 403
    if not _validate_backup_csrf():
        return jsonify({"success": False, "message": "Token de segurança inválido. Recarregue a página."}), 400

    senha_backup = (request.form.get("backup_password") or "").strip()
    server_backup_id = request.form.get("backup_id", type=int)

    if not senha_backup:
        return jsonify({"success": False, "message": "Informe a senha de criptografia do arquivo de backup."}), 400

    try:
        if server_backup_id:
            registro = db.session.get(BackupHistorico, server_backup_id)
            if not registro:
                return jsonify({"success": False, "message": "Backup selecionado não encontrado."}), 404
            safe_name = os.path.basename(registro.nome_arquivo)
            caminho = os.path.join(backup_service.get_backup_dir(app.root_path), safe_name)
            if not os.path.isfile(caminho):
                return jsonify({"success": False, "message": "Arquivo físico não está mais disponível no servidor."}), 404
            with open(caminho, "rb") as f_in:
                enc_bytes = f_in.read()
            origem_nome = safe_name
        else:
            arquivo = request.files.get("backup_file")
            if not arquivo or not arquivo.filename:
                return jsonify({"success": False, "message": "Selecione um arquivo '.g360bkp' para inspecionar."}), 400
            enc_bytes = arquivo.read()
            origem_nome = os.path.basename(arquivo.filename)

        preview, _ = backup_service.inspect_backup_bytes(db, enc_bytes, senha_backup)
        staging_token = backup_service.stage_uploaded_backup(app.root_path, enc_bytes)

        manifest = preview["manifest"]
        return jsonify(
            {
                "success": True,
                "staging_token": staging_token,
                "filename": origem_nome,
                "sha256": preview["sha256"],
                "size_fmt": _formatar_tamanho(preview["size_bytes"]),
                "created_at_br": manifest.get("created_at_br"),
                "created_by": manifest.get("created_by"),
                "observacao": manifest.get("observacao") or "",
                "source_dialect": manifest.get("source_dialect"),
                "totals": manifest.get("totals"),
                "comparison": preview["comparison"],
                "warnings": preview["warnings"],
            }
        )
    except backup_service.BackupError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro ao inspecionar backup: {str(e)}"}), 500


@app.route("/api/backup/restaurar", methods=["POST"])
@login_required
def api_backup_restaurar():
    if not _is_backup_admin():
        return jsonify({"success": False, "message": "Acesso não autorizado."}), 403
    if not _validate_backup_csrf():
        return jsonify({"success": False, "message": "Token de segurança inválido. Recarregue a página."}), 400

    data = request.get_json(silent=True) or request.form
    staging_token = (data.get("staging_token") or "").strip()
    backup_password = (data.get("backup_password") or "").strip()
    admin_password = data.get("admin_password") or ""
    confirm_phrase = (data.get("confirm_phrase") or "").strip().upper()

    if confirm_phrase != "RESTAURAR TUDO":
        return jsonify({"success": False, "message": "Digite exatamente a frase de confirmação: RESTAURAR TUDO"}), 400
    if not current_user.check_password(admin_password):
        return jsonify({"success": False, "message": "Senha do administrador logado está incorreta."}), 403

    admin_id_anterior = current_user.id
    admin_username_anterior = current_user.username
    ip_origem = request.remote_addr
    stg_path = None

    try:
        enc_bytes, stg_path = backup_service.read_staged_backup(app.root_path, staging_token)
        resultado = backup_service.restore_full_backup(
            db=db,
            app_root=app.root_path,
            encrypted_bytes=enc_bytes,
            password=backup_password,
            restored_by=admin_username_anterior,
            safety_password=backup_password,
            post_restore_hook=atualizar_schema,
        )

        # Registra o Auto-Snapshot de Segurança e o Evento de Restauração no BackupHistorico
        sb = resultado["safety_backup"]
        sb_totals = sb["manifest"]["totals"]
        reg_safety = BackupHistorico(
            nome_arquivo=sb["filename"],
            tipo="PRE_RESTORE",
            status="CONCLUIDO",
            tamanho_bytes=sb["size_bytes"],
            sha256=sb["sha256"],
            total_tabelas=sb_totals["tables"],
            total_registros=sb_totals["records"],
            total_arquivos=sb_totals["media_files"],
            origem_banco=sb["manifest"]["source_dialect"],
            observacao=sb["manifest"].get("observacao") or "Snapshot automático pré-restauração",
            criado_por_id=admin_id_anterior,
            criado_por_nome=f"AUTO ({admin_username_anterior})",
            ip_origem=ip_origem,
            data_hora=datetime.utcnow(),
        )
        reg_restore = BackupHistorico(
            nome_arquivo=f"RESTORE_{resultado['backup_created_at'] or ''}".strip(),
            tipo="RESTAURACAO",
            status="CONCLUIDO",
            tamanho_bytes=len(enc_bytes),
            sha256=backup_service._sha256_bytes(enc_bytes),
            total_tabelas=len(resultado["restored_tables"]),
            total_registros=resultado["restored_records"],
            total_arquivos=resultado["restored_media_files"],
            origem_banco=db.engine.dialect.name,
            observacao=f"Restauração completa aplicada a partir do backup de {resultado['backup_created_at']}. Auto-snapshot salvo em {sb['filename']}.",
            criado_por_id=admin_id_anterior,
            criado_por_nome=admin_username_anterior,
            ip_origem=ip_origem,
            data_hora=datetime.utcnow(),
        )
        db.session.add(reg_safety)
        db.session.add(reg_restore)
        db.session.commit()

        # Verifica se o usuário atual ainda existe após a restauração
        user_ainda_existe = db.session.get(User, admin_id_anterior)
        require_relogin = user_ainda_existe is None
        if user_ainda_existe:
            registrar_log(
                "RESTAUROU BACKUP COMPLETO",
                f"Backup de {resultado['backup_created_at']} ({resultado['restored_records']} registros, {resultado['restored_media_files']} mídias)",
            )
        else:
            log_sys = LogAuditoria(
                usuario_id=None,
                acao="RESTAUROU BACKUP COMPLETO",
                alvo=f"Restaurado por {admin_username_anterior} (backup de {resultado['backup_created_at']})",
                ip_origem=ip_origem,
                rota_acessada=request.path[:250],
            )
            db.session.add(log_sys)
            db.session.commit()
            logout_user()

        return jsonify(
            {
                "success": True,
                "message": f"Sistema restaurado com sucesso! {resultado['restored_records']} registros e {resultado['restored_media_files']} arquivos de mídia foram recuperados.",
                "restored_records": resultado["restored_records"],
                "restored_media_files": resultado["restored_media_files"],
                "safety_backup_filename": sb["filename"],
                "safety_backup_download_url": url_for("admin_backup_download", backup_id=reg_safety.id),
                "require_relogin": require_relogin,
            }
        )
    except backup_service.BackupError as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Falha na restauração (rollback aplicado, nenhum dado alterado): {str(e)}"}), 500
    finally:
        if stg_path and os.path.isfile(stg_path):
            try:
                os.remove(stg_path)
            except OSError:
                pass


# === APENAS UM BLOCO DE EXECUÇÃO NO FINAL DO ARQUIVO ===
# --- 1. EXECUTA TANTO LOCALMENTE QUANTO NO RAILWAY (GUNICORN) ---
with app.app_context():
    db.create_all()
    atualizar_schema()
    create_admin()

# --- 2. EXECUTA APENAS NO SEU COMPUTADOR (LOCAL) ---
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")