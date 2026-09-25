from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import (
    abort,
    jsonify,
    redirect,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    logout_user,
)

from database.models import (
    ROLE_ADMIN,
    ROLE_USER,
    ROLES_VALIDAS,
    Usuario,
    agora_utc,
    session,
)

login_manager = LoginManager()


def init_auth(app):
    """
    Inicializa o Flask-Login na aplicação Flask.

    Deve ser chamado uma única vez no app.py:

        init_auth(app)
    """

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    # Mensagem padrão utilizada pelo Flask-Login.
    login_manager.login_message = "Faça login para acessar esta página."

    login_manager.login_message_category = "warning"

    # Melhora a proteção da sessão.
    login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(user_id):
    """
    Carrega o usuário salvo na sessão do Flask-Login.

    Usuários inexistentes ou inativos não são carregados.
    """

    try:
        usuario_id = int(user_id)

    except (TypeError, ValueError):
        return None

    usuario = session.get(
        Usuario,
        usuario_id,
    )

    if usuario is None:
        return None

    if not usuario.ativo:
        return None

    return usuario


def is_api_request():
    """
    Identifica se a requisição atual espera uma resposta JSON.

    Isso permite utilizar os mesmos decorators tanto nas
    páginas HTML quanto nas futuras rotas /api/.
    """

    if request.path.startswith("/api/"):
        return True

    if request.is_json:
        return True

    melhor_resposta = request.accept_mimetypes.best

    if melhor_resposta == "application/json":
        return True

    return False


@login_manager.unauthorized_handler
def usuario_nao_autenticado():
    """
    Tratamento para tentativa de acesso sem login.

    API:
        retorna HTTP 401 em JSON.

    Navegação normal:
        redireciona para /login.
    """

    if is_api_request():

        return (
            jsonify(
                {
                    "success": False,
                    "error": ("AUTHENTICATION_REQUIRED"),
                    "message": ("Autenticação necessária."),
                }
            ),
            401,
        )

    return redirect(
        url_for(
            "auth.login",
            next=request.url,
        )
    )


def normalizar_username(username):
    """
    Normaliza o username antes de consultar ou cadastrar.

    Exemplos:

        " ADMIN " -> "admin"
        "Fiscal"   -> "fiscal"
    """

    if username is None:
        return ""

    return str(username).strip().lower()


def buscar_usuario_por_username(username):
    """
    Busca um usuário pelo username normalizado.
    """
    username = normalizar_username(username)
    if not username:
        return None

    return session.query(Usuario).filter(Usuario.username == username).first()


def autenticar_usuario(username, password):
    """
    Valida username + senha.
    Retorna:
        Usuario -> autenticação válida
        None    -> autenticação inválida

    Também registra a data/hora do último login válido.

    IMPORTANTE:
    esta função NÃO executa login_user().
    O app.py fará isso posteriormente.
    """
    username = normalizar_username(username)

    if not username or not password:
        return None

    usuario = buscar_usuario_por_username(username)

    if usuario is None:
        return None

    if not usuario.ativo:
        return None

    if not usuario.check_password(password):
        return None

    usuario.ultimo_login = agora_utc()

    try:
        session.commit()

    except Exception:
        session.rollback()
        raise

    return usuario


def validar_role(role):
    """
    Valida e normaliza um perfil de usuário.

    Retorna:
        ADMIN
        USER

    Lança ValueError para valores inválidos.
    """
    if role is None:
        raise ValueError("Perfil do usuário não informado.")

    role = str(role).strip().upper()

    if role not in ROLES_VALIDAS:
        raise ValueError(
            "Perfil inválido. "
            f"Valores permitidos: "
            f"{', '.join(sorted(ROLES_VALIDAS))}."
        )

    return role


def validar_nova_senha(password):
    """
    Valida uma nova senha antes de criar usuário
    ou redefinir sua senha.

    Retorna:
        (True, None)

    ou:

        (False, "motivo")
    """
    if password is None:
        return (
            False,
            "A senha não foi informada.",
        )

    password = str(password)
    if len(password) < 10:
        return (
            False,
            ("A senha deve possuir " "pelo menos 10 caracteres."),
        )

    if not any(caractere.islower() for caractere in password):
        return (
            False,
            ("A senha deve possuir " "pelo menos uma letra minúscula."),
        )

    if not any(caractere.isupper() for caractere in password):
        return (
            False,
            ("A senha deve possuir " "pelo menos uma letra maiúscula."),
        )

    if not any(caractere.isdigit() for caractere in password):
        return (
            False,
            ("A senha deve possuir " "pelo menos um número."),
        )

    return (
        True,
        None,
    )


def role_required(*roles):
    """
    Decorator genérico para restringir uma rota
    a determinados perfis.

    Exemplo:

        @role_required("ADMIN")
        def pagina():
            ...

    ou:

        @role_required("ADMIN", "USER")
        def pagina():
            ...
    """

    roles_normalizadas = {validar_role(role) for role in roles}

    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            if not current_user.is_active:
                logout_user()

                if is_api_request():
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": ("USER_DISABLED"),
                                "message": ("Usuário inativo."),
                            }
                        ),
                        401,
                    )

                return redirect(url_for("auth.login"))

            if current_user.role not in roles_normalizadas:
                if is_api_request():
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": ("PERMISSION_DENIED"),
                                "message": (
                                    "Você não possui "
                                    "permissão para "
                                    "executar esta ação."
                                ),
                            }
                        ),
                        403,
                    )

                abort(403)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def admin_required(func):
    """
    Atalho para rotas exclusivas de administradores.

    Uso:

        @app.route("/admin")
        @admin_required
        def admin():
            ...
    """
    return role_required(ROLE_ADMIN)(func)


def user_required(func):
    """
    Permite tanto ADMIN quanto USER.

    Na maioria das rotas normais, @login_required já seria
    suficiente.

    Este decorator existe para deixar permissões explícitas
    quando necessário.
    """

    return role_required(
        ROLE_ADMIN,
        ROLE_USER,
    )(func)


def password_change_allowed(func):
    """
    Decorator destinado a rotas que podem ser acessadas
    mesmo quando o usuário está marcado para trocar a senha.

    Atualmente funciona apenas como login_required.

    Existe para mantermos explícita a intenção das rotas
    de alteração de senha.
    """

    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def password_change_required(func):
    """
    Impede acesso normal quando o administrador marcou
    o usuário para trocar a senha no próximo login.

    Futuramente poderá ser aplicado nas páginas internas.

    O próprio endpoint/tela de troca de senha NÃO deverá
    utilizar este decorator.
    """

    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):

        if current_user.trocar_senha_proximo_login:

            if is_api_request():

                return (
                    jsonify(
                        {
                            "success": False,
                            "error": ("PASSWORD_CHANGE_REQUIRED"),
                            "message": (
                                "É necessário alterar "
                                "sua senha antes de "
                                "continuar."
                            ),
                        }
                    ),
                    403,
                )

            return redirect(url_for("auth.alterar_senha"))

        return func(*args, **kwargs)

    return wrapper


def url_destino_segura(target):
    """
    Verifica se uma URL de redirecionamento pertence
    ao próprio sistema.

    Evita vulnerabilidade de Open Redirect.

    Exemplo perigoso:

        /login?next=https://site-malicioso.com

    retorna False.
    """
    if not target:
        return False

    host_url = request.host_url

    referencia = urlparse(host_url)

    destino = urlparse(
        urljoin(
            host_url,
            target,
        )
    )

    return (
        destino.scheme
        in {
            "http",
            "https",
        }
        and referencia.netloc == destino.netloc
    )


def obter_url_pos_login(target=None):
    """
    Retorna um destino seguro após o login.

    Se o parâmetro fornecido for inválido,
    retorna a página inicial.
    """
    if target and url_destino_segura(target):
        return target
    return url_for("main.index")
