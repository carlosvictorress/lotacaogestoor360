import os
import csv
import io
import uuid
import locale
import pdfplumber
import pandas as pd
import re  # <--- ADICIONE ESTA LINHA AQUI
import base64
from datetime import date
from datetime import date
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime
from sqlalchemy import func, text

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'chave_secreta_local')
# Pega a URL do banco da variável de ambiente (Railway) ou usa o SQLite local como plano B
db_url = os.getenv('DATABASE_URL')

# Truque necessário: o SQLAlchemy exige "postgresql://" mas o Railway às vezes envia "postgres://"
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///banco_local.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELOS ---

class Secretaria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    usuarios = db.relationship('User', backref='secretaria', lazy=True)
    funcionarios = db.relationship('Funcionario', backref='secretaria', lazy=True)

class Funcao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

class LocalTrabalho(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

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
    role = db.Column(db.String(20), default='rh_secretaria') # admin, rh_supervisor, rh_secretaria
    secretaria_id = db.Column(db.Integer, db.ForeignKey('secretaria.id'), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LogAuditoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    usuario = db.relationship('User', backref='logs')
    acao = db.Column(db.String(50), nullable=False)
    alvo = db.Column(db.String(200), nullable=False)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)

class HistoricoLotacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    funcionario_id = db.Column(db.Integer, db.ForeignKey('funcionario.id'), nullable=False)
    funcionario = db.relationship('Funcionario', backref='historico_movimentacao')
    antiga_secretaria = db.Column(db.String(100))
    antigo_local = db.Column(db.String(100))
    antiga_funcao = db.Column(db.String(100))
    data_mudanca = db.Column(db.DateTime, default=datetime.utcnow)
    quem_mudou_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    quem_mudou = db.relationship('User')

class Funcionario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_validacao = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    validado = db.Column(db.Boolean, default=False)
    secretaria_id = db.Column(db.Integer, db.ForeignKey('secretaria.id'), nullable=False)
    criado_por = db.Column(db.Integer, db.ForeignKey('user.id'))
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    foi_indicacao = db.Column(db.Boolean, default=False)
    padrinho_id = db.Column(db.Integer, db.ForeignKey('padrinho.id'), nullable=True)
    padrinho = db.relationship('Padrinho', backref='indicados')
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

    funcao_id = db.Column(db.Integer, db.ForeignKey('funcao.id'))
    funcao = db.relationship('Funcao', backref='funcionarios')
    local_trabalho_id = db.Column(db.Integer, db.ForeignKey('local_trabalho.id'))
    local_trabalho = db.relationship('LocalTrabalho', backref='funcionarios')

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


class RegistroPonto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    funcionario_id = db.Column(db.Integer, db.ForeignKey('funcionario.id'), nullable=False)
    funcionario = db.relationship('Funcionario', backref='registros_ponto')
    data_hora = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    tipo = db.Column(db.String(20), default='batida', nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    precisao = db.Column(db.Float, nullable=True)
    foto_path = db.Column(db.String(255), nullable=True)
    
class RescisaoHistorico(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    cpf = db.Column(db.String(14))
    funcao = db.Column(db.String(100))
    data_inicio = db.Column(db.Date)
    data_saida = db.Column(db.Date)
    data_geracao = db.Column(db.DateTime, default=datetime.utcnow)    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def parse_date(date_str):
    if not date_str: return None
    try: return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError: return None

def normalizar_cpf(cpf):
    """Remove caracteres especiais do CPF deixando apenas números"""
    if not cpf: return ""
    return ''.join(filter(str.isdigit, cpf))

@app.template_filter('mask_cpf')
def mask_cpf(value):
    if not value: return ""
    # Remove tudo que não for dígito para garantir a contagem correta
    digits = ''.join(filter(str.isdigit, value))
    if len(digits) == 11:
        return f"***.{digits[3:6]}.{digits[6:9]}-**"
    return value

def registrar_log(acao, alvo):
    try:
        user_id = current_user.id if current_user.is_authenticated else None
        log = LogAuditoria(usuario_id=user_id, acao=acao, alvo=alvo)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Erro log: {e}")

@app.context_processor
def inject_global_data():
    data = {'pending_count': 0, 'notifications': []}
    if current_user.is_authenticated:
        if current_user.role == 'admin' or getattr(current_user, 'is_admin', False):
            try:
                data['pending_count'] = Funcionario.query.filter_by(validado=False).count()
            except:
                pass
        try:
            data['notifications'] = LogAuditoria.query.order_by(LogAuditoria.data_hora.desc()).limit(5).all()
        except:
            pass
    return data

# --- ROTAS ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin else url_for('sistema'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('user')
        password = request.form.get('pass')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('sistema'))
        else:
            flash('Login inválido.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/validar', methods=['GET'])
def validar_documento():
    token = request.args.get('codigo')
    funcionario = None
    erro = None
    if token:
        funcionario = Funcionario.query.filter_by(token_validacao=token).first()
        if not funcionario:
            erro = "Documento Inválido ou Não Encontrado."
    return render_template('validar.html', funcionario=funcionario, erro=erro, codigo_digitado=token)

@app.route('/get_historico/<int:id>')
@login_required
def get_historico(id):
    if not current_user.is_admin: return "Acesso negado", 403
    hist = HistoricoLotacao.query.filter_by(funcionario_id=id).order_by(HistoricoLotacao.data_mudanca.desc()).all()
    html = ""
    if not hist:
        html = '<tr><td colspan="4" class="text-center p-4 text-gray-500">Nenhuma movimentação registrada.</td></tr>'
    for h in hist:
        nome_usuario = h.quem_mudou.username if h.quem_mudou else "Sistema"
        html += f"""<tr class="border-b border-gray-100"><td class="p-3 text-xs text-gray-500">{h.data_mudanca.strftime('%d/%m/%Y %H:%M')}</td><td class="p-3 text-sm font-medium">{h.antiga_secretaria}<br><span class="text-xs text-gray-400">{h.antigo_local}</span></td><td class="p-3 text-sm">{h.antiga_funcao}</td><td class="p-3 text-xs text-blue-600 font-bold">{nome_usuario}</td></tr>"""
    return html

@app.route('/validar_cadastros')
@login_required
def validar_cadastros():
    if current_user.role != 'admin' and not getattr(current_user, 'is_admin', False):
        flash('Acesso não autorizado.', 'error')
        return redirect(url_for('sistema'))

    secretaria_id = request.args.get('secretaria_id')
    busca = request.args.get('busca')
    page = request.args.get('page', 1, type=int)
    
    query = Funcionario.query
    if secretaria_id:
        query = query.filter_by(secretaria_id=secretaria_id)
    if busca:
        term = f"%{busca.upper()}%"
        query = query.filter((Funcionario.nome.like(term)) | (Funcionario.cpf.like(term)))
    
    pagination = query.order_by(Funcionario.validado.asc(), Funcionario.nome.asc()).paginate(page=page, per_page=20, error_out=False)
    funcionarios = pagination.items
    secretarias = Secretaria.query.order_by(Secretaria.nome).all()
    return render_template('validar_cadastros.html', funcionarios=funcionarios, secretarias=secretarias, pagination=pagination)

@app.route('/aprovar_cadastro/<int:id>')
@login_required
def aprovar_cadastro(id):
    if current_user.role != 'admin' and not getattr(current_user, 'is_admin', False):
        flash('Acesso não autorizado.', 'error')
        return redirect(url_for('sistema'))
    func = db.session.get(Funcionario, id)
    if func:
        func.validado = True
        db.session.commit()
        flash(f'Cadastro de {func.nome} validado com sucesso!', 'success')
    return redirect(url_for('validar_cadastros'))

@app.route('/revogar_validacao/<int:id>')
@login_required
def revogar_validacao(id):
    if current_user.role != 'admin' and not getattr(current_user, 'is_admin', False):
        flash('Acesso não autorizado.', 'error')
        return redirect(url_for('sistema'))
    func = db.session.get(Funcionario, id)
    if func:
        func.validado = False
        db.session.commit()
        flash(f'Validação de {func.nome} revogada com sucesso!', 'success')
    return redirect(url_for('validar_cadastros'))

@app.route('/exportar_pendentes')
@login_required
def exportar_pendentes():
    if current_user.role != 'admin' and not getattr(current_user, 'is_admin', False):
        flash('Acesso não autorizado.', 'error')
        return redirect(url_for('sistema'))

    secretaria_id = request.args.get('secretaria_id')
    busca = request.args.get('busca')
    
    query = Funcionario.query.filter_by(validado=False)

    if secretaria_id:
        query = query.filter_by(secretaria_id=secretaria_id)
    if busca:
        term = f"%{busca.upper()}%"
        query = query.filter((Funcionario.nome.like(term)) | (Funcionario.cpf.like(term)))
    
    funcionarios = query.order_by(Funcionario.nome.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['Nome', 'CPF', 'Secretaria', 'Função', 'Vínculo', 'Data Criação'])
    for f in funcionarios:
        writer.writerow([f.nome, f.cpf, f.secretaria.nome, f.funcao.nome if f.funcao else '', f.tipo_vinculo, f.data_criacao.strftime('%d/%m/%Y')])
    output.seek(0)
    return Response('\ufeff' + output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=pendentes_validacao.csv"})

@app.route('/recisoes')
@login_required
def pagina_recisoes():
    # Servidores ativos para o select/busca
    ativos = Funcionario.query.order_by(Funcionario.nome).all()
    # Histórico de quem já saiu
    historico = RescisaoHistorico.query.order_by(RescisaoHistorico.data_geracao.desc()).all()
    return render_template('recisao_painel.html', ativos=ativos, historico=historico)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin: 
        return redirect(url_for('sistema'))
    
    if request.method == 'POST':
        # CRIAR SECRETARIA
        if 'create_secretaria' in request.form:
            nome_sec = request.form.get('nome_secretaria').upper()
            if not Secretaria.query.filter_by(nome=nome_sec).first():
                db.session.add(Secretaria(nome=nome_sec))
                db.session.commit()
                registrar_log("CRIOU SECRETARIA", nome_sec)
                flash('Secretaria criada!', 'success')

        # CRIAR FUNCAO
        if 'create_funcao' in request.form:
            nome_funcao = request.form.get('nome_funcao').upper()
            if not Funcao.query.filter_by(nome=nome_funcao).first():
                db.session.add(Funcao(nome=nome_funcao))
                db.session.commit()
                flash('Função criada!', 'success')

        # CRIAR LOCAL
        if 'create_local' in request.form:
            nome_local = request.form.get('nome_local').upper()
            if not LocalTrabalho.query.filter_by(nome=nome_local).first():
                db.session.add(LocalTrabalho(nome=nome_local))
                db.session.commit()
                flash('Local de Trabalho criado!', 'success')

        # CRIAR PADRINHO
        if 'create_padrinho' in request.form:
            nome_padrinho = request.form.get('nome_padrinho').upper()
            if not Padrinho.query.filter_by(nome=nome_padrinho).first():
                db.session.add(Padrinho(nome=nome_padrinho))
                db.session.commit()
                flash('Padrinho/Indicador criado!', 'success')
        
        # CRIAR USUÁRIO
        elif 'create_user' in request.form:
            username = request.form.get('username')
            sec_id_form = request.form.get('secretaria_id')
            role_form = request.form.get('role')
            
            if not sec_id_form:
                flash('Erro: Selecione uma Secretaria para o usuário!', 'error')
            elif not User.query.filter_by(username=username).first():
                is_admin_bool = (role_form == 'admin')
                u = User(username=username, secretaria_id=int(sec_id_form), role=role_form, is_admin=is_admin_bool)
                u.set_password(request.form.get('password'))
                db.session.add(u)
                db.session.commit()
                registrar_log("CRIOU USUÁRIO", f"{username} (Sec ID: {sec_id_form})")
                flash(f'Usuário {username} criado com sucesso!', 'success')
            else:
                flash('Usuário já existe!', 'error')

    # --- LÓGICA DE FILTRAGEM (CORRIGIDA) ---
    filtro_secretaria = request.args.get('secretaria_id')
    filtro_vinculo = request.args.get('tipo_vinculo')
    filtro_indicacao = request.args.get('padrinho_id') # Mantido como string para o filtro
    filtro_funcao = request.args.get('funcao_id')
    filtro_local = request.args.get('local_trabalho_id')
    busca_termo = request.args.get('busca_termo') 
    
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
        query = query.filter((Funcionario.nome.like(termo)) | (Funcionario.cpf.like(termo)))

    funcionarios_filtrados = query.order_by(Funcionario.nome).all()
    total_filtrado = len(funcionarios_filtrados)

    # Carregamento de dados para o Dashboard
    lista_padrinhos = Padrinho.query.order_by(Padrinho.nome).all()

    stats_sec_query = db.session.query(Secretaria.nome, func.count(Funcionario.id)).join(Funcionario).group_by(Secretaria.nome).all()
    stats_secretaria = {s[0]: s[1] for s in stats_sec_query}
    
    stats_vinculo_query = db.session.query(Funcionario.tipo_vinculo, func.count(Funcionario.id)).group_by(Funcionario.tipo_vinculo).all()
    stats_vinculo = { (v[0] if v[0] else "Não Informado"): v[1] for v in stats_vinculo_query }
    
    count_validados = Funcionario.query.filter_by(validado=True).count()
    count_pendentes = Funcionario.query.filter_by(validado=False).count()
    stats_validacao = {'Aptos': count_validados, 'Pendentes': count_pendentes}

    locais_stats_query = db.session.query(LocalTrabalho.nome, func.count(Funcionario.id))\
        .join(Funcionario, Funcionario.local_trabalho_id == LocalTrabalho.id)
    if filtro_secretaria:
        locais_stats_query = locais_stats_query.filter(Funcionario.secretaria_id == filtro_secretaria)
    locais_stats = locais_stats_query.group_by(LocalTrabalho.nome).order_by(func.count(Funcionario.id).desc()).all()

    logs = LogAuditoria.query.order_by(LogAuditoria.data_hora.desc()).limit(100).all()
    secretarias = Secretaria.query.all()
    users = User.query.order_by(User.username).all()
    funcoes = Funcao.query.order_by(Funcao.nome).all()
    locais_trabalho = LocalTrabalho.query.order_by(LocalTrabalho.nome).all()

    return render_template('admin.html', 
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
                           filtros={'sec': filtro_secretaria, 'vinculo': filtro_vinculo, 'indicacao': filtro_indicacao, 'busca': busca_termo, 'funcao': filtro_funcao, 'local': filtro_local}, 
                           role=current_user.role, 
                           is_admin=current_user.is_admin)

@app.route('/processar_recisao', methods=['POST'])
@login_required
def processar_recisao():
    id_func = request.form.get('id_funcionario')
    dt_ini = parse_date(request.form.get('data_inicio'))
    dt_sai = parse_date(request.form.get('data_saida'))
    
    funcionario = db.session.get(Funcionario, id_func)
    if not funcionario:
        flash("Servidor não encontrado", "error")
        return redirect(url_for('pagina_recisoes'))

    try:
        # 1. Salva no histórico de rescisões
        nova_rescisao = RescisaoHistorico(
            nome=funcionario.nome,
            cpf=funcionario.cpf,
            funcao=funcionario.funcao.nome if funcionario.funcao else 'N/A',
            data_inicio=dt_ini,
            data_saida=dt_sai
        )
        db.session.add(nova_rescisao)

        # 2. Dados para o documento (mantendo sua lógica anterior)
        dados_doc = {
            'nome': funcionario.nome,
            'funcao': funcionario.funcao.nome if funcionario.funcao else 'N/A',
            'dt_inicio': dt_ini.strftime('%d/%m/%Y'),
            'dt_saida': dt_sai.strftime('%d/%m/%Y')
        }

        # 3. Exclui o servidor da base ativa (limpando FKs)
        HistoricoLotacao.query.filter_by(funcionario_id=funcionario.id).delete()
        RegistroPonto.query.filter_by(funcionario_id=funcionario.id).delete()
        db.session.delete(funcionario)
        
        db.session.commit()
        registrar_log("GEROU RESCISAO", dados_doc['nome'])

        # Prepara data por extenso para o papel
        meses = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"]
        hoje = datetime.now()
        data_extenso = f"{hoje.day} de {meses[hoje.month - 1]} de {hoje.year}"

        return render_template('recisao_documento.html', f=dados_doc, data_atual=data_extenso)
        
    except Exception as e:
        db.session.rollback()
        flash(f"Erro: {str(e)}", "error")
        return redirect(url_for('pagina_recisoes'))
        
    
    
@app.route('/admin/reconhecimento_facial')
@login_required
def reconhecimento_facial():
    if not current_user.is_admin:
        return redirect(url_for('sistema'))
    
    # Busca todos os funcionários para a galeria
    funcionarios = Funcionario.query.order_by(Funcionario.nome).all()
    return render_template('reconhecimento_facial.html', lista_funcionarios=funcionarios)    

    
@app.route('/admin/cargos_total')
@login_required
def cargos_total():
    if not current_user.is_admin:
        return redirect(url_for('sistema'))

    # Pega todos os funcionários e suas funções
    funcionarios = Funcionario.query.all()
    
    stats_cargos = {}
    for f in funcionarios:
        nome_cargo = f.funcao.nome if f.funcao else "SEM CARGO"
        if nome_cargo not in stats_cargos:
            stats_cargos[nome_cargo] = {"total": 0, "servidores": []}
        
        stats_cargos[nome_cargo]["total"] += 1
        stats_cargos[nome_cargo]["servidores"].append({
            "nome": f.nome,
            "cpf": f.cpf,
            "local": f.local_trabalho.nome if f.local_trabalho else "NÃO DEFINIDO",
            "vinculo": f.tipo_vinculo
        })

    # Ordena os cargos por nome
    stats_cargos = dict(sorted(stats_cargos.items()))

    return render_template('cargos_total.html', stats_cargos=stats_cargos)    

@app.route('/excluir_ficha/<int:id>')
@login_required
def excluir_ficha(id):
    if not current_user.is_admin:
        flash('Apenas Admin pode excluir.', 'error')
        return redirect(url_for('sistema'))
    ficha = db.session.get(Funcionario, id)
    if ficha:
        nome = ficha.nome
        HistoricoLotacao.query.filter_by(funcionario_id=id).delete()
        db.session.delete(ficha)
        db.session.commit()
        registrar_log("EXCLUIU FICHA", nome)
        flash('Ficha excluída.', 'success')
    return redirect(url_for('sistema'))

@app.route('/admin/update_user', methods=['POST'])
@login_required
def update_user():
    if not current_user.is_admin: return redirect(url_for('sistema'))
    
    user_id = request.form.get('user_id')
    u = db.session.get(User, user_id)
    
    if u:
        # Username
        new_username = request.form.get('username')
        if new_username and new_username != u.username:
            if User.query.filter_by(username=new_username).first():
                flash('Nome de usuário já existe!', 'error')
                return redirect(url_for('admin_dashboard'))
            u.username = new_username
            
        # Senha
        new_password = request.form.get('password')
        if new_password:
            u.set_password(new_password)
            
        # Secretaria e Role
        sec_id = request.form.get('secretaria_id')
        role = request.form.get('role')
        
        if sec_id: u.secretaria_id = int(sec_id)
        if role:
            u.role = role
            u.is_admin = (role == 'admin')
            
        db.session.commit()
        registrar_log("EDITOU USUÁRIO", u.username)
        flash('Usuário atualizado com sucesso!', 'success')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return redirect(url_for('sistema'))
    u = db.session.get(User, user_id)
    if u and not u.is_admin:
        db.session.delete(u)
        db.session.commit()
        flash('Usuário excluído.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_secretaria/<int:sec_id>')
@login_required
def delete_secretaria(sec_id):
    if not current_user.is_admin: return redirect(url_for('sistema'))
    if User.query.filter_by(secretaria_id=sec_id).first() or Funcionario.query.filter_by(secretaria_id=sec_id).first():
        flash('Erro: Existem vínculos.', 'error')
    else:
        s = db.session.get(Secretaria, sec_id)
        if s:
            db.session.delete(s)
            db.session.commit()
            flash('Secretaria excluída.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_funcao/<int:id>')
@login_required
def delete_funcao(id):
    if not current_user.is_admin: return redirect(url_for('sistema'))
    if Funcionario.query.filter_by(funcao_id=id).first():
        flash('Erro: Existem funcionários com esta função.', 'error')
    else:
        f = db.session.get(Funcao, id)
        if f: db.session.delete(f); db.session.commit(); flash('Função excluída.', 'success')
    return redirect(url_for('admin_dashboard')+"?tab=config")

@app.route('/admin/delete_local/<int:id>')
@login_required
def delete_local(id):
    if not current_user.is_admin: return redirect(url_for('sistema'))
    if Funcionario.query.filter_by(local_trabalho_id=id).first():
        flash('Erro: Existem funcionários neste local.', 'error')
    else:
        l = db.session.get(LocalTrabalho, id)
        if l: db.session.delete(l); db.session.commit(); flash('Local de trabalho excluído.', 'success')
    return redirect(url_for('admin_dashboard')+"?tab=config")

@app.route('/admin/delete_padrinho/<int:id>')
@login_required
def delete_padrinho(id):
    if not current_user.is_admin: return redirect(url_for('sistema'))
    if Funcionario.query.filter_by(padrinho_id=id).first():
        flash('Erro: Existem funcionários indicados por este padrinho.', 'error')
    else:
        p = db.session.get(Padrinho, id)
        if p: db.session.delete(p); db.session.commit(); flash('Padrinho/Indicador excluído.', 'success')
    return redirect(url_for('admin_dashboard')+"?tab=config")

@app.route('/exportar_excel')
@login_required
def exportar_excel():
    # 1. Verificação de permissão
    if not current_user.is_admin: 
        return redirect(url_for('sistema'))

    # 2. Captura dos filtros da URL
    filtro_secretaria = request.args.get('secretaria_id')
    filtro_vinculo = request.args.get('tipo_vinculo')
    filtro_indicacao = request.args.get('padrinho_id')
    filtro_funcao = request.args.get('funcao_id')
    filtro_local = request.args.get('local_trabalho_id')

    # 3. Construção da Query
    query = Funcionario.query
    if filtro_secretaria: query = query.filter_by(secretaria_id=filtro_secretaria)
    if filtro_vinculo: query = query.filter_by(tipo_vinculo=filtro_vinculo)
    if filtro_indicacao: query = query.filter_by(padrinho_id=filtro_indicacao)
    if filtro_funcao: query = query.filter_by(funcao_id=filtro_funcao)
    if filtro_local: query = query.filter_by(local_trabalho_id=filtro_local)
    
    funcionarios = query.order_by(Funcionario.nome).all()

    # 4. Preparação do CSV
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')

    # Cabeçalho idêntico aos campos do add_server do Gestor360
    header = [
        'Nº CONTRATO', 'NOME', 'CPF', 'RG', 'DATA NASCIMENTO', 'NOME DA MÃE', 
        'EMAIL', 'PIS/PASEP', 'VÍNCULO', 'LOCAL', 'ESCOLA_ID', 'CLASSE/NÍVEL', 
        'Nº CONTRA CHEQUE', 'NACIONALIDADE', 'ESTADO CIVIL', 'TELEFONE', 
        'ENDEREÇO', 'FUNÇÃO', 'LOTAÇÃO', 'CARGA HORÁRIA', 'REMUNERAÇÃO', 
        'DADOS BANCÁRIOS', 'DATA INÍCIO', 'DATA SAÍDA', 'OBSERVAÇÕES'
    ]
    writer.writerow(header)

    # 5. Preenchimento dos dados com tratamento de erros
    for f in funcionarios:
        writer.writerow([
            getattr(f, 'num_contrato', ''),
            f.nome,
            f.cpf,
            getattr(f, 'rg', ''),
            f.data_nascimento.strftime('%Y-%m-%d') if getattr(f, 'data_nascimento', None) else '',
            getattr(f, 'nome_mae', ''),
            getattr(f, 'email', ''),
            getattr(f, 'pis_pasep', ''),
            f.tipo_vinculo,
            f.local_trabalho.nome if getattr(f, 'local_trabalho', None) else '',
            getattr(f, 'escola_id', ''),
            getattr(f, 'classe_nivel', ''),
            getattr(f, 'num_contra_cheque', ''),
            getattr(f, 'nacionalidade', ''),
            getattr(f, 'estado_civil', ''),
            getattr(f, 'telefone', ''),
            getattr(f, 'endereco', ''),
            f.funcao.nome if getattr(f, 'funcao', None) else '',
            getattr(f, 'lotacao', ''),
            getattr(f, 'carga_horaria', ''),
            getattr(f, 'remuneracao', 0),
            getattr(f, 'dados_bancarios', ''),
            f.data_inicio.strftime('%Y-%m-%d') if getattr(f, 'data_inicio', None) else '',
            f.data_saida.strftime('%Y-%m-%d') if getattr(f, 'data_saida', None) else '',
            getattr(f, 'observacoes', '')
        ])

    # 6. Finalização e Log
    output.seek(0)
    registrar_log("EXPORTOU DADOS", f"Relatório completo ({len(funcionarios)} registros)")

    # Retorno com utf-8-sig para garantir acentuação correta no Excel (Windows)
    return Response(
        output.getvalue().encode("utf-8-sig"),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment;filename=exportacao_servidores_completa.csv"
        }
    )

def gerar_proximo_vinculo():
    """Gera o próximo número de vínculo no formato NUMERO/ANO."""
    ano_atual = datetime.now().year
    # Busca todos os vínculos do ano atual para processar em memória
    vinculos_ano = db.session.query(Funcionario.num_vinculo).filter(Funcionario.num_vinculo.like(f'%/{ano_atual}')).all()
    max_num = 0
    for v_tuple in vinculos_ano:
        v_str = v_tuple[0]
        if v_str and '/' in v_str:
            try:
                num_parte = int(v_str.split('/')[0])
                if num_parte > max_num:
                    max_num = num_parte
            except (ValueError, IndexError):
                continue # Ignora formatos inválidos
    proximo_numero = max_num + 1
    return f"{proximo_numero}/{ano_atual}"

@app.route('/sistema', methods=['GET', 'POST'])
@login_required
def sistema():
    # Carrega todas as opções para os formulários
    secretarias_opcoes = Secretaria.query.order_by(Secretaria.nome).all() if current_user.is_admin else []
    funcoes_opcoes = Funcao.query.order_by(Funcao.nome).all()
    locais_opcoes = LocalTrabalho.query.order_by(LocalTrabalho.nome).all()
    padrinhos_opcoes = Padrinho.query.order_by(Padrinho.nome).all()

    nome_secretaria_atual = current_user.secretaria.nome if current_user.secretaria else "Sem Secretaria"
    if current_user.is_admin: nome_secretaria_atual = "MODO ADMINISTRADOR"

    if request.method == 'POST':
        is_indicacao = True if request.form.get('foi_indicacao') == 'sim' else False
        padrinho_id = request.form.get('padrinho_id') if is_indicacao and request.form.get('padrinho_id') else None
        
        # LÓGICA DE SECRETARIA
        if current_user.is_admin:
            sec_id = request.form.get('secretaria_id')
            if not sec_id:
                flash('Selecione a Secretaria!', 'error')
                return redirect(url_for('sistema'))
            sec_obj = db.session.get(Secretaria, int(sec_id))
            lotacao_texto = sec_obj.nome
        else:
            sec_id = current_user.secretaria_id
            lotacao_texto = current_user.secretaria.nome if current_user.secretaria else "ADMINISTRAÇÃO"

        dados_form = {
            'nome': request.form.get('nome').upper(),
            'num_vinculo': request.form.get('num_vinculo'),
            'cpf': request.form.get('cpf'),
            'rg': request.form.get('rg'),
            'data_expedicao_rg': parse_date(request.form.get('data_expedicao_rg')),
            'data_nasc': parse_date(request.form.get('data_nasc')),
            'pis': request.form.get('pis'),
            'titulo_eleitor': request.form.get('titulo_eleitor'),
            'zona_eleitoral': request.form.get('zona_eleitoral'),
            'secao_eleitoral': request.form.get('secao_eleitoral'),
            'mae': request.form.get('mae').upper(),
            'nacionalidade': request.form.get('nacionalidade'),
            'estado_civil': request.form.get('estado_civil'),
            'telefone': request.form.get('telefone'),
            'email': request.form.get('email'),
            'endereco': request.form.get('endereco').upper(),
            'funcao_id': request.form.get('funcao_id') or None,
            'local_trabalho_id': request.form.get('local_trabalho_id') or None,
            'tipo_vinculo': request.form.get('tipo_vinculo'),
            'classe': request.form.get('classe'),
            'contracheque': request.form.get('contracheque'),
            'remuneracao': request.form.get('remuneracao'),
            'jornada_trabalho': request.form.get('jornada_trabalho'),
            'dt_inicio': parse_date(request.form.get('dt_inicio')),
            'dt_termino': parse_date(request.form.get('dt_termino')),
            'banco': request.form.get('banco'),
            'agencia': request.form.get('agencia'),
            'conta': request.form.get('conta'),
            'tipo_conta': request.form.get('tipo_conta'),
            'foi_indicacao': is_indicacao,
            'padrinho_id': padrinho_id,
            'secretaria_id': int(sec_id), # Força inteiro
            'lotacao': lotacao_texto,
            'crianca_assistida': request.form.get('crianca_assistida').strip().upper() if request.form.get('crianca_assistida') and request.form.get('crianca_assistida').strip() else None
        }

        func_id = request.form.get('id')
        
        # Se for um novo cadastro, o campo num_vinculo é gerado automaticamente
        # e sobrescreve qualquer valor que venha do formulário.
        if not func_id:
            dados_form['num_vinculo'] = gerar_proximo_vinculo()

        # Validação de CPF duplicado
        cpf_normalizado = normalizar_cpf(dados_form['cpf'])
        cpf_duplicado = False
        if cpf_normalizado and len(cpf_normalizado) == 11:  # CPF válido tem 11 dígitos
            # Busca funcionários com o mesmo CPF
            funcionarios_com_mesmo_cpf = Funcionario.query.filter_by(cpf=dados_form['cpf']).all()
            
            # Se for edição, remove o próprio funcionário da lista
            if func_id:
                funcionarios_com_mesmo_cpf = [f for f in funcionarios_com_mesmo_cpf if f.id != int(func_id)]
            
            # Se encontrou duplicados, mostra alerta
            if funcionarios_com_mesmo_cpf:
                cpf_duplicado = True
                nomes_duplicados = [f.nome for f in funcionarios_com_mesmo_cpf]
                flash(f'⚠️ ATENÇÃO: Este CPF já está cadastrado para: {", ".join(nomes_duplicados)}. Verifique se não está duplicando o cadastro.', 'error')
                # Continua o processo mas alerta o usuário
        
        if func_id:
            funcionario = db.session.get(Funcionario, func_id)
            if funcionario:
                mudou_local = (str(funcionario.local_trabalho_id) != str(dados_form['local_trabalho_id']))
                mudou_sec = (str(funcionario.secretaria_id) != str(sec_id))
                mudou_funcao = (str(funcionario.funcao_id) != str(dados_form['funcao_id']))
                
                if mudou_local or mudou_sec or mudou_funcao:
                    nova_funcao_obj = db.session.get(Funcao, dados_form['funcao_id'])
                    novo_local_obj = db.session.get(LocalTrabalho, dados_form['local_trabalho_id'])
                    historico = HistoricoLotacao(
                        funcionario_id=funcionario.id,
                        antiga_secretaria=funcionario.lotacao,
                        antigo_local=funcionario.local_trabalho.nome if funcionario.local_trabalho else "N/A",
                        antiga_funcao=funcionario.funcao.nome if funcionario.funcao else "N/A",
                        quem_mudou_id=current_user.id
                    )
                    db.session.add(historico)
                    registrar_log("MOVIMENTOU", f"{funcionario.nome} -> {novo_local_obj.nome if novo_local_obj else 'N/A'}")
                else:
                    registrar_log("EDITOU", funcionario.nome)

                for key, value in dados_form.items():
                    setattr(funcionario, key, value)
                
                db.session.commit()
                if not cpf_duplicado:
                    flash('Dados atualizados com sucesso!', 'success')
        else:
            novo_func = Funcionario(**dados_form)
            novo_func.criado_por = current_user.id
            db.session.add(novo_func)
            db.session.commit()
            registrar_log("CRIOU FICHA", f"{novo_func.nome} ({lotacao_texto})")
            if not cpf_duplicado:
                flash('Ficha criada com sucesso!', 'success')

        return redirect(url_for('sistema'))

    query = Funcionario.query
    if not current_user.is_admin:
        query = query.filter_by(secretaria_id=current_user.secretaria_id)
    lista_funcionarios = query.order_by(Funcionario.id.desc()).all()
    proximo_vinculo_form = gerar_proximo_vinculo()
    
    # Pega o ID da função de apoio para a lógica do modal no frontend
    funcao_apoio = Funcao.query.filter(Funcao.nome == 'PROFISSIONAL DE APOIO / CUIDADOR').first()
    funcao_apoio_id = funcao_apoio.id if funcao_apoio else None

    return render_template('sistema.html', 
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
                           funcao_apoio_id=funcao_apoio_id)

def create_admin():
    with app.app_context():
        db.create_all()
        user = User.query.filter_by(username='admin').first()
        if not user:
            # Verifica se a secretaria já existe para não duplicar
            sec_adm = Secretaria.query.filter_by(nome="PREFEITURA MUNICIPAL").first()
            if not sec_adm:
                sec_adm = Secretaria(nome="PREFEITURA MUNICIPAL")
                db.session.add(sec_adm)
                db.session.commit()
            
            # Pega a senha de uma variável de ambiente ou usa uma padrão apenas na primeira vez
            senha_inicial = os.getenv('ADMIN_INITIAL_PASSWORD', 'Mudar123@')
            
            user = User(username='admin', is_admin=True, role='admin', secretaria_id=sec_adm.id)
            user.set_password(senha_inicial)
            db.session.add(user)
            db.session.commit()
            print(f"ADMINISTRADOR CRIADO COM SENHA INICIAL: {senha_inicial}")

def atualizar_schema():
    """Função auxiliar para adicionar colunas novas em bancos existentes"""
    with app.app_context():
        with db.engine.connect() as conn:
            colunas = [
                ("padrinho_id", "INTEGER REFERENCES padrinho(id)"),
                ("funcao_id", "INTEGER REFERENCES funcao(id)"),
                ("local_trabalho_id", "INTEGER REFERENCES local_trabalho(id)"),
                ("validado", "BOOLEAN DEFAULT 0"),
                ("data_expedicao_rg", "DATE"),
                ("jornada_trabalho", "VARCHAR(50)"),
                ("crianca_assistida", "VARCHAR(150)")
            ]
            for col, tipo in colunas:
                try:
                    conn.execute(text(f"ALTER TABLE funcionario ADD COLUMN {col} {tipo}"))
                    conn.commit()
                    print(f"SCHEMA ATUALIZADO: Coluna '{col}' adicionada.")
                except Exception:
                    pass


# Tente configurar para PT-BR para datas por extenso
try:
    locale.setlocale(locale.LC_TIME, 'pt_BR.utf8')
except:
    pass

@app.route('/imprimir_encaminhamento/<int:id>')
@login_required
def imprimir_encaminhamento(id):
    funcionario = db.session.get(Funcionario, id)
    if not funcionario:
        return "Funcionário não encontrado", 404
        
    hoje = datetime.now()
    meses = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
    data_extenso = f"{hoje.day} de {meses[hoje.month - 1]} de {hoje.year}"
    
    return render_template('encaminhamento.html', 
                           funcionario=funcionario, 
                           data_extenso=data_extenso, 
                           ano=hoje.year)

@app.route('/apoio_pedagogico')
@login_required
def apoio_pedagogico():
    if not current_user.is_admin:
        flash('Acesso não autorizado.', 'error')
        return redirect(url_for('sistema'))
    
    cuidadores = Funcionario.query.join(Funcao).filter(
        Funcao.nome == 'PROFISSIONAL DE APOIO / CUIDADOR',
        Funcionario.crianca_assistida.isnot(None)
    ).order_by(Funcionario.crianca_assistida).all()
    return render_template('apoio_pedagogico.html', cuidadores=cuidadores)

@app.route('/fotos')
@login_required
def gerenciar_fotos():
    funcionarios = Funcionario.query.order_by(Funcionario.nome).all()
    return render_template('fotos.html', funcionarios=funcionarios)    

@app.route('/admin/folha_pagamento', methods=['GET'])
@login_required
def folha_pagamento():
    if not current_user.is_admin:
        return redirect(url_for('sistema'))

    locais_trabalho = LocalTrabalho.query.order_by(LocalTrabalho.nome).all()
    
    local_id_filtro = request.args.get('local_id')
    funcionarios_folha = []
    local_selecionado = None

    if local_id_filtro:
        funcionarios_folha = Funcionario.query.filter_by(local_trabalho_id=local_id_filtro).order_by(Funcionario.nome).all()
        local_selecionado = db.session.get(LocalTrabalho, local_id_filtro)

    return render_template('folha_pagamento.html', 
                           locais_trabalho=locais_trabalho,
                           funcionarios_folha=funcionarios_folha,
                           local_selecionado=local_selecionado)


@app.route('/admin/ponto', methods=['GET'])
@login_required
def painel_ponto():
    """Painel interno para visualizar registros de ponto de todos os servidores."""
    # Permite admin, RH secretaria e supervisor (visualização).
    if not (getattr(current_user, 'is_admin', False) or current_user.role in ['admin', 'rh_secretaria', 'rh_supervisor']):
        return redirect(url_for('sistema'))

    secretaria_id = request.args.get('secretaria_id')
    busca_nome = request.args.get('busca_nome')
    mes = request.args.get('mes')
    # Horários esperados (entrada 1 e retorno)
    inicio_20 = request.args.get('inicio_20', '07:00')
    inicio_40 = request.args.get('inicio_40', '07:00')
    entrada_2 = request.args.get('entrada_2', '13:30')
    tolerancia_min = request.args.get('tolerancia_min', '0')

    if not mes:
        mes = datetime.utcnow().strftime('%Y-%m')

    try:
        tolerancia_min = int(tolerancia_min)
    except:
        tolerancia_min = 0

    def parse_hhmm(hhmm):
        try:
            hh, mm = str(hhmm).split(':', 1)
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
            num = int(''.join([c for c in str(jornada_str) if c.isdigit()]))
            if num in (20, 40):
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
            elif (jornada in (None, 20, 40)):
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
    start_month = datetime.strptime(mes, '%Y-%m')
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

    query_mes = query.filter(RegistroPonto.data_hora >= start_month, RegistroPonto.data_hora < end_month)

    # Para a tabela (performance)
    registros = (query_mes
                 .order_by(RegistroPonto.data_hora.desc())
                 .limit(1000)
                 .all())

    # Para o resumo (atraso por servidor)
    entradas_mes = (query_mes
                     .filter(RegistroPonto.tipo == 'entrada')
                     .order_by(RegistroPonto.data_hora.desc())
                     .all())

    # Calcula atraso considerando:
    # - primeira entrada do dia (entrada_idx=0)
    # - retorno do intervalo (entrada_idx=1)
    # Soma em minutos e depois converte para horas no resumo.
    entradas_por_dia = {}
    for e in entradas_mes:
        if not getattr(e, 'data_hora', None):
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
            atraso = calcular_atraso_min(e.data_hora, e.funcionario.jornada_trabalho, idx)
            entry_id_to_atraso[e.id] = atraso
            atraso_total_geral_min += atraso

            if func_id not in resumo:
                resumo[func_id] = {
                    'funcionario_id': func_id,
                    'nome': e.funcionario.nome,
                    'total_minutos': 0,
                    'total_horas': 0.0,
                }
            resumo[func_id]['total_minutos'] += atraso

    # Atribui atraso por linha (apenas para entradas exibidas no limite da tabela)
    for r in registros:
        r.atraso_minutos = 0
        if getattr(r, 'tipo', None) == 'entrada':
            r.atraso_minutos = entry_id_to_atraso.get(r.id, 0)

    for key, v in resumo.items():
        v['total_horas'] = round(v['total_minutos'] / 60.0, 2)

    resumo_servidores = list(resumo.values())
    resumo_servidores.sort(key=lambda x: x['total_minutos'], reverse=True)

    return render_template('ponto_admin.html',
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
                           resumo_servidores=resumo_servidores)

@app.route('/exportar_migracao')
@login_required
def exportar_migracao():
    funcionarios = Funcionario.query.all()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    
    # Cabeçalho que o Gestor 360 espera ler
    header = [
        "Nº CONTRATO", "NOME", "CPF", "RG", "DATA NASCIMENTO", 
        "NOME DA MÃE", "EMAIL", "PIS/PASEP", "VÍNCULO", "LOCAL", 
        "ESCOLA_ID", "CLASSE/NÍVEL", "Nº CONTRA CHEQUE", "NACIONALIDADE", 
        "ESTADO CIVIL", "TELEFONE", "ENDEREÇO", "FUNÇÃO", "LOTAÇÃO", 
        "CARGA HORÁRIA", "REMUNERAÇÃO", "DADOS BANCÁRIOS", 
        "DATA INÍCIO", "DATA SAÍDA", "OBSERVAÇÕES"
    ]
    writer.writerow(header)
    
    def formatar_data(dt):
        if not dt: return ""
        try:
            return dt.strftime('%Y-%m-%d')
        except:
            return ""

    for f in funcionarios:
        # Garantia contra Erro 404
        contrato = f.num_vinculo if f.num_vinculo else f"MIG-{f.id}"
        
        # Lógica para Dados Bancários (unindo os campos do seu formulário)
        dados_bancarios = f"Bco: {f.banco}, Ag: {f.agencia}, Cta: {f.conta}" if f.banco else ""

        writer.writerow([
            contrato,                                         # Nº CONTRATO
            f.nome.upper() if f.nome else "",                 # NOME
            f.cpf if f.cpf else "",                           # CPF
            f.rg if f.rg else "",                             # RG
            formatar_data(f.data_nasc),                       # DATA NASCIMENTO (Confirmado: data_nasc)
            f.mae.upper() if f.mae else "",                   # NOME DA MÃE (Confirmado: mae)
            f.email if f.email else "",                       # EMAIL
            f.pis if f.pis else "",                           # PIS/PASEP (Confirmado: pis)
            f.tipo_vinculo if f.tipo_vinculo else "CONTRATADO",# VÍNCULO
            f.local_trabalho.nome if f.local_trabalho else "SEME", # LOCAL
            f.local_trabalho_id if f.local_trabalho_id else "",# ESCOLA_ID (Usando local_trabalho_id)
            f.classe if f.classe else "",                     # CLASSE/NÍVEL
            f.contracheque if f.contracheque else "",         # Nº CONTRA CHEQUE
            f.nacionalidade if f.nacionalidade else "BRASILEIRA",# NACIONALIDADE
            f.estado_civil if f.estado_civil else "SOLTEIRO(A)", # ESTADO CIVIL
            f.telefone if f.telefone else "",                 # TELEFONE
            f.endereco.upper() if f.endereco else "",         # ENDEREÇO
            f.funcao.nome if f.funcao else "AUXILIAR",        # FUNÇÃO
            f.lotacao if f.lotacao else "EDUCAÇÃO",           # LOTAÇÃO
            f.jornada_trabalho if f.jornada_trabalho else "40",# CARGA HORÁRIA
            f.remuneracao if f.remuneracao else "0.00",       # REMUNERAÇÃO
            dados_bancarios,                                  # DADOS BANCÁRIOS
            formatar_data(f.dt_inicio),                       # DATA INÍCIO (Confirmado: dt_inicio)
            formatar_data(f.dt_termino),                      # DATA SAÍDA (Confirmado: dt_termino)
            "Migração automática Ficha2026"                   # OBSERVAÇÕES
        ])
    
    output.seek(0)
    return Response(
        output.getvalue().encode('utf-8-sig'), 
        mimetype="text/csv", 
        headers={"Content-Disposition": "attachment;filename=migracao_pronta_gestor360.csv"}
    )
    
@app.route('/admin/movimentar_servidor', methods=['POST'])
@login_required
def movimentar_servidor():
    if not current_user.is_admin:
        flash('Acesso não autorizado.', 'error')
        return redirect(url_for('sistema'))

    func_id = request.form.get('funcionario_id')
    nova_funcao_id = request.form.get('nova_funcao_id')
    novo_local_id = request.form.get('novo_local_id')

    funcionario = db.session.get(Funcionario, func_id)

    if not funcionario:
        flash('Funcionário não encontrado.', 'error')
        return redirect(url_for('admin_dashboard'))

    mudou_funcao = str(funcionario.funcao_id) != str(nova_funcao_id)
    mudou_local = str(funcionario.local_trabalho_id) != str(novo_local_id)

    if not mudou_funcao and not mudou_local:
        flash('Nenhuma alteração foi feita.', 'info')
        return redirect(url_for('admin_dashboard', tab='dados'))

    # Registrar histórico ANTES de mudar
    historico = HistoricoLotacao(
        funcionario_id=funcionario.id,
        antiga_secretaria=funcionario.secretaria.nome if funcionario.secretaria else "N/A",
        antigo_local=funcionario.local_trabalho.nome if funcionario.local_trabalho else "N/A",
        antiga_funcao=funcionario.funcao.nome if funcionario.funcao else "N/A",
        quem_mudou_id=current_user.id
    )
    db.session.add(historico)

    if mudou_funcao: funcionario.funcao_id = nova_funcao_id
    if mudou_local: funcionario.local_trabalho_id = novo_local_id

    registrar_log("MOVIMENTOU", f"Servidor: {funcionario.nome}")
    db.session.commit()
    flash(f'Servidor {funcionario.nome} movimentado com sucesso!', 'success')
    
    return redirect(url_for('admin_dashboard', tab='dados'))

# Executa atualizações ao carregar a aplicação (funciona com flask run)
with app.app_context():
    create_admin()
    atualizar_schema()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
    
def processar_pdf_para_excel(pdf_path, output_excel):
    dados = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            # Extrai tabelas da página
            table = page.extract_table()
            if table:
                dados.extend(table[1:]) # Ignora o cabeçalho de cada página
    
    # Criar DataFrame
    df = pd.DataFrame(dados, columns=["NOME_CPF", "LOTACAO_LOCAL", "FUNCAO_VINCULO", "QUEM_INDICOU"])
    
    # Exportar para Excel com abas por Local
    with pd.ExcelWriter(output_excel) as writer:
        for local, group in df.groupby("LOTACAO_LOCAL"):
            group.to_excel(writer, sheet_name=str(local)[:31], index=False)    

@app.route('/importar_pdf_para_excel', methods=['GET', 'POST'])
@login_required
def importar_pdf_para_excel():
    if not current_user.is_admin:
        return redirect(url_for('sistema'))

    if request.method == 'POST':
        file = request.files.get('pdf_file')
        if file:
            # Processamento básico do PDF
            with pdfplumber.open(file) as pdf:
                todas_linhas = []
                for page in pdf.pages:
                    table = page.extract_table()
                    if table:
                        todas_linhas.extend(table[1:]) # Ignora cabeçalhos repetidos
            
            df = pd.DataFrame(todas_linhas, columns=["NOME_CPF", "LOTACAO_LOCAL", "FUNCAO_VINCULO", "QUEM_INDICOU"])
            
            # Gerar Excel em memória
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                # Agrupa por Colégio/Local
                for local, group in df.groupby("LOTACAO_LOCAL"):
                    sheet_name = str(local)[:31].replace("/", "-") # Limita nome da aba
                    group.to_excel(writer, sheet_name=sheet_name, index=False)
            
            output.seek(0)
            return Response(output, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            headers={"Content-Disposition": "attachment;filename=relatorio_organizado.xlsx"})

    return render_template('importar_pdf.html')       

@app.route('/importar_pdf', methods=['GET', 'POST'])
@login_required
def importar_pdf():
    if not current_user.is_admin: return redirect(url_for('sistema'))
    
    if request.method == 'POST':
        file = request.files.get('pdf_file')
        if file:
            with pdfplumber.open(file) as pdf:
                texto_paginas = [page.extract_text() for page in pdf.pages]
            
            dados = []
            # O padrão busca CPF no formato XXX.XXX.XXX-XX
            padrao_cpf = r'\d{3}\.\d{3}\.\d{3}-\d{2}'
            
            for texto in texto_paginas:
                if not texto: continue
                linhas = texto.split('\n')
                for i, linha in enumerate(linhas):
                    # Se achamos um CPF, assumimos que a linha anterior é o Nome
                    if re.search(padrao_cpf, linha):
                        nome = linhas[i-1].strip() if i > 0 else "N/A"
                        cpf = re.search(padrao_cpf, linha).group()
                        
                        # Tenta pegar local e função nas linhas seguintes
                        local = linhas[i+1].strip() if i+1 < len(linhas) else ""
                        funcao = linhas[i+2].strip() if i+2 < len(linhas) else ""
                        
                        dados.append([nome, cpf, local, funcao])

            df = pd.DataFrame(dados, columns=["NOME", "CPF", "LOCAL", "FUNCAO"])
            
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                # Agrupa por Local para criar abas automáticas
                for local, group in df.groupby("LOCAL"):
                    nome_aba = str(local)[:31].replace("/", "-").replace("*", "")
                    group.to_excel(writer, sheet_name=nome_aba or "SemLocal", index=False)
            
            output.seek(0)
            return Response(output.getvalue(), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            headers={"Content-Disposition": "attachment;filename=lotoes_organizado.xlsx"})
                            
    return render_template('importar_pdf.html')                            


@app.route('/ponto/<token>', methods=['GET'])
def pagina_ponto(token):
    """Página pública para o servidor bater ponto via QRCode."""
    funcionario = Funcionario.query.filter_by(token_validacao=token).first()
    if not funcionario:
        return render_template('ponto.html', funcionario=None, erro="Servidor não encontrado ou QRCode inválido.")
    
    # Últimos registros de ponto para exibir histórico rápido
    registros = (RegistroPonto.query
                 .filter_by(funcionario_id=funcionario.id)
                 .order_by(RegistroPonto.data_hora.desc())
                 .limit(10)
                 .all())
    return render_template('ponto.html', funcionario=funcionario, registros=registros, erro=None)


@app.route('/ponto/<token>/registrar', methods=['POST'])
def registrar_ponto(token):
    """Recebe dados de geolocalização e foto e grava o ponto."""
    funcionario = Funcionario.query.filter_by(token_validacao=token).first()
    if not funcionario:
        flash('Servidor não encontrado ou QRCode inválido.', 'error')
        return redirect(url_for('pagina_ponto', token=token))

    lat = request.form.get('lat')
    lng = request.form.get('lng')
    acc = request.form.get('acc')
    tipo = request.form.get('tipo')
    foto_base64 = request.form.get('foto_base64')

    foto_path_rel = None
    if foto_base64:
        try:
            # Remove prefixo data:image/...;base64,
            if ',' in foto_base64:
                foto_base64 = foto_base64.split(',', 1)[1]
            foto_bytes = base64.b64decode(foto_base64)

            fotos_dir = os.path.join(app.root_path, 'static', 'ponto_fotos')
            os.makedirs(fotos_dir, exist_ok=True)

            filename = f"{funcionario.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.jpg"
            file_path = os.path.join(fotos_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(foto_bytes)

            foto_path_rel = f"ponto_fotos/{filename}"
        except Exception as e:
            print(f"Erro ao salvar foto de ponto: {e}")

    registro = RegistroPonto(
        funcionario_id=funcionario.id,
        tipo=tipo if tipo in ['entrada', 'saida'] else 'batida',
        latitude=float(lat) if lat else None,
        longitude=float(lng) if lng else None,
        precisao=float(acc) if acc else None,
        foto_path=foto_path_rel
    )
    db.session.add(registro)
    db.session.commit()

    flash('Ponto registrado com sucesso!', 'success')
    return redirect(url_for('pagina_ponto', token=token))

@app.route('/gerar_rescisao_excluir/<int:id>')
@login_required
def gerar_rescisao_excluir(id):
    funcionario = db.session.get(Funcionario, id)
    if not funcionario:
        flash("Funcionário não encontrado", "error")
        return redirect(url_for('sistema'))
        
    # 1. Criamos um dicionário com os dados ANTES de deletar para usar no template
    dados_rescisao = {
        'nome': funcionario.nome,
        'dt_inicio': funcionario.dt_inicio,
        'dt_termino': funcionario.dt_termino,
        'funcao_nome': funcionario.funcao.nome if funcionario.funcao else 'N/A'
    }
    
    try:
        # 2. Registra o log primeiro
        registrar_log("RESCISAO E EXCLUSAO", funcionario.nome)

        # 3. CORREÇÃO DO ERRO: Deletar registros vinculados manualmente
        # Remove histórico e pontos antes para evitar violação de integridade (FK)
        HistoricoLotacao.query.filter_by(funcionario_id=id).delete()
        RegistroPonto.query.filter_by(funcionario_id=id).delete()
        
        # 4. Agora deleta o funcionário
        db.session.delete(funcionario)
        db.session.commit()
        
        # 5. Prepara data atual para o termo
        meses = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"]
        hoje = datetime.now()
        data_extenso = f"{hoje.day} de {meses[hoje.month - 1]} de {hoje.year}"
        
        # 6. Renderiza a página de rescisão (certifique-se de ter o rescisao.html)
        return render_template('recisao.html', funcionario=dados_rescisao, data_atual=data_extenso)
        
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao excluir: {e}")
        flash("Erro ao processar exclusão no banco de dados.", "error")
        return redirect(url_for('sistema'))


