import os
import csv
import io
import uuid
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
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///banco_local.db')
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
    quem_indicou = db.Column(db.String(150), nullable=True)
    nome = db.Column(db.String(150), nullable=False)
    num_vinculo = db.Column(db.String(50))
    cpf = db.Column(db.String(14))
    rg = db.Column(db.String(20))
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
    funcao = db.Column(db.String(100))
    lotacao = db.Column(db.String(100))
    local_trabalho = db.Column(db.String(100))
    tipo_vinculo = db.Column(db.String(50))
    classe = db.Column(db.String(50))
    contracheque = db.Column(db.String(50))
    remuneracao = db.Column(db.String(20))
    dt_inicio = db.Column(db.Date)
    dt_termino = db.Column(db.Date)
    banco = db.Column(db.String(50))
    agencia = db.Column(db.String(20))
    conta = db.Column(db.String(20))
    tipo_conta = db.Column(db.String(20))

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
        writer.writerow([f.nome, f.cpf, f.secretaria.nome, f.funcao, f.tipo_vinculo, f.data_criacao.strftime('%d/%m/%Y')])
    output.seek(0)
    return Response('\ufeff' + output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=pendentes_validacao.csv"})

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin: return redirect(url_for('sistema'))
    
    if request.method == 'POST':
        # CRIAR SECRETARIA
        if 'create_secretaria' in request.form:
            nome_sec = request.form.get('nome_secretaria').upper()
            if not Secretaria.query.filter_by(nome=nome_sec).first():
                db.session.add(Secretaria(nome=nome_sec))
                db.session.commit()
                registrar_log("CRIOU SECRETARIA", nome_sec)
                flash('Secretaria criada!', 'success')
        
        # CRIAR USUÁRIO (CORRIGIDO)
        elif 'create_user' in request.form:
            username = request.form.get('username')
            sec_id_form = request.form.get('secretaria_id')
            role_form = request.form.get('role')
            
            if not sec_id_form:
                flash('Erro: Selecione uma Secretaria para o usuário!', 'error')
            elif not User.query.filter_by(username=username).first():
                # Garante que o ID seja inteiro
                is_admin_bool = (role_form == 'admin')
                u = User(username=username, secretaria_id=int(sec_id_form), role=role_form, is_admin=is_admin_bool)
                u.set_password(request.form.get('password'))
                db.session.add(u)
                db.session.commit()
                registrar_log("CRIOU USUÁRIO", f"{username} (Sec ID: {sec_id_form})")
                flash(f'Usuário {username} criado com sucesso!', 'success')
            else:
                flash('Usuário já existe!', 'error')

    # Filtros
    filtro_secretaria = request.args.get('secretaria_id')
    filtro_vinculo = request.args.get('tipo_vinculo')
    filtro_funcao = request.args.get('funcao')
    filtro_indicacao = request.args.get('quem_indicou')
    busca_cpf = request.args.get('cpf')
    
    query = Funcionario.query
    if filtro_secretaria: query = query.filter_by(secretaria_id=filtro_secretaria)
    if filtro_vinculo: query = query.filter_by(tipo_vinculo=filtro_vinculo)
    if filtro_indicacao: query = query.filter_by(quem_indicou=filtro_indicacao)
    if filtro_funcao: query = query.filter(Funcionario.funcao.like(f'%{filtro_funcao.upper()}%'))
    if busca_cpf: query = query.filter(Funcionario.cpf.like(f'%{busca_cpf}%'))

    funcionarios_filtrados = query.order_by(Funcionario.nome).all()
    total_filtrado = len(funcionarios_filtrados)

    indicadores_query = db.session.query(Funcionario.quem_indicou).distinct().filter(Funcionario.quem_indicou != None, Funcionario.quem_indicou != "").all()
    lista_indicadores = [i[0] for i in indicadores_query]

    stats_sec_query = db.session.query(Secretaria.nome, func.count(Funcionario.id)).join(Funcionario).group_by(Secretaria.nome).all()
    stats_secretaria = {s[0]: s[1] for s in stats_sec_query}
    stats_vinculo_query = db.session.query(Funcionario.tipo_vinculo, func.count(Funcionario.id)).group_by(Funcionario.tipo_vinculo).all()
    stats_vinculo = {v[0]: v[1] for v in stats_vinculo_query if v[0]}
    
    count_validados = Funcionario.query.filter_by(validado=True).count()
    count_pendentes = Funcionario.query.filter_by(validado=False).count()
    stats_validacao = {'Aptos': count_validados, 'Pendentes': count_pendentes}

    locais_query = db.session.query(Funcionario.local_trabalho, func.count(Funcionario.id))
    if filtro_secretaria: locais_query = locais_query.filter_by(secretaria_id=filtro_secretaria)
    locais_stats = locais_query.group_by(Funcionario.local_trabalho).order_by(func.count(Funcionario.id).desc()).all()

    logs = LogAuditoria.query.order_by(LogAuditoria.data_hora.desc()).limit(100).all()
    secretarias = Secretaria.query.all()
    users = User.query.order_by(User.username).all()

    return render_template('admin.html', secretarias=secretarias, users=users, funcionarios=funcionarios_filtrados, total_geral=total_filtrado, stats_secretaria=stats_secretaria, stats_vinculo=stats_vinculo, stats_validacao=stats_validacao, locais_stats=locais_stats, lista_indicadores=lista_indicadores, logs=logs, filtros={'sec': filtro_secretaria, 'vinculo': filtro_vinculo, 'funcao': filtro_funcao, 'indicacao': filtro_indicacao, 'cpf': busca_cpf}, role=current_user.role, is_admin=current_user.is_admin)

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

@app.route('/exportar_excel')
@login_required
def exportar_excel():
    if not current_user.is_admin: return redirect(url_for('sistema'))
    filtro_secretaria = request.args.get('secretaria_id')
    query = Funcionario.query
    if filtro_secretaria: query = query.filter_by(secretaria_id=filtro_secretaria)
    funcionarios = query.all()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['Nome', 'CPF', 'Secretaria', 'Local', 'Função', 'Vínculo', 'Token'])
    for f in funcionarios:
        writer.writerow([f.nome, f.cpf, f.secretaria.nome, f.local_trabalho, f.funcao, f.tipo_vinculo, f.token_validacao])
    output.seek(0)
    registrar_log("EXPORTOU DADOS", "Relatório Excel")
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=relatorio.csv"})

@app.route('/sistema', methods=['GET', 'POST'])
@login_required
def sistema():
    secretarias_opcoes = Secretaria.query.all() if current_user.is_admin else []
    nome_secretaria_atual = current_user.secretaria.nome if current_user.secretaria else "Sem Secretaria"
    if current_user.is_admin: nome_secretaria_atual = "MODO ADMINISTRADOR"

    if request.method == 'POST':
        is_indicacao = True if request.form.get('foi_indicacao') == 'sim' else False
        quem_indicou = request.form.get('quem_indicou').upper() if is_indicacao else None
        
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
            'funcao': request.form.get('funcao').upper(),
            'local_trabalho': request.form.get('local_trabalho').upper(),
            'tipo_vinculo': request.form.get('tipo_vinculo'),
            'classe': request.form.get('classe'),
            'contracheque': request.form.get('contracheque'),
            'remuneracao': request.form.get('remuneracao'),
            'dt_inicio': parse_date(request.form.get('dt_inicio')),
            'dt_termino': parse_date(request.form.get('dt_termino')),
            'banco': request.form.get('banco'),
            'agencia': request.form.get('agencia'),
            'conta': request.form.get('conta'),
            'tipo_conta': request.form.get('tipo_conta'),
            'foi_indicacao': is_indicacao,
            'quem_indicou': quem_indicou,
            'secretaria_id': int(sec_id), # Força inteiro
            'lotacao': lotacao_texto
        }

        func_id = request.form.get('id')
        
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
                mudou_local = (funcionario.local_trabalho != dados_form['local_trabalho'])
                mudou_sec = (str(funcionario.secretaria_id) != str(sec_id))
                
                if mudou_local or mudou_sec:
                    historico = HistoricoLotacao(
                        funcionario_id=funcionario.id,
                        antiga_secretaria=funcionario.lotacao,
                        antigo_local=funcionario.local_trabalho,
                        antiga_funcao=funcionario.funcao,
                        quem_mudou_id=current_user.id
                    )
                    db.session.add(historico)
                    registrar_log("MOVIMENTOU", f"{funcionario.nome} -> {dados_form['local_trabalho']}")
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
    
    return render_template('sistema.html', nome_usuario=current_user.username, nome_secretaria=nome_secretaria_atual, lista_funcionarios=lista_funcionarios, secretarias_opcoes=secretarias_opcoes, is_admin=current_user.is_admin, role=current_user.role)

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
        try:
            with db.engine.connect() as conn:
                # Tenta adicionar a coluna 'validado' se ela não existir
                conn.execute(text("ALTER TABLE funcionario ADD COLUMN validado BOOLEAN DEFAULT 0"))
                conn.commit()
                print("SCHEMA ATUALIZADO: Coluna 'validado' adicionada com sucesso.")
        except Exception as e:
            # Se der erro, provavelmente a coluna já existe, então ignoramos
            pass

if __name__ == '__main__':
    create_admin()
    atualizar_schema()
    app.run(debug=True, host='0.0.0.0')