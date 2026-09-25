from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    confirm_login,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from auth.audit_service import (
    ACAO_LOGIN_FALHA,
    ACAO_LOGIN_SUCESSO,
    ACAO_LOGOUT,
    ACAO_SENHA_ALTERADA,
    registrar_auditoria,
    registrar_falha,
)
from auth.auth_utils import (
    autenticar_usuario,
    is_api_request,
    normalizar_username,
    obter_url_pos_login,
    password_change_allowed,
    validar_nova_senha,
)
from database.models import agora_utc, session

auth_bp = Blueprint("auth", __name__)


# ============================================================
# SERIALIZAÇÃO
# ============================================================
def serializar_usuario_logado(usuario):
    return {
        "id": usuario.id,
        "username": usuario.username,
        "nome": usuario.nome,
        "role": usuario.role,
        "is_admin": usuario.is_admin,
        "ativo": usuario.ativo,
        "trocar_senha_proximo_login": (usuario.trocar_senha_proximo_login),
        "ultimo_login": (
            usuario.ultimo_login.isoformat() if usuario.ultimo_login else None
        ),
    }


# ============================================================
# LOGIN
# ============================================================
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Login para páginas HTML e API.

    Aceita:
    application/json
    ou
    form-data / x-www-form-urlencoded
    """
    if current_user.is_authenticated:
        if current_user.trocar_senha_proximo_login:
            return redirect(url_for("auth.alterar_senha"))

        return redirect(url_for("main.index"))

    if request.method == "GET":
        return render_template("login.html")

    # --------------------------------------------------------
    # RECEBE DADOS
    # --------------------------------------------------------
    if request.is_json:
        dados = request.get_json(silent=True) or {}
        username = dados.get("username")
        password = dados.get("password")
        next_url = dados.get("next")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        next_url = request.form.get("next") or request.args.get("next")

    username_normalizado = normalizar_username(username)

    # --------------------------------------------------------
    # AUTENTICAÇÃO
    # --------------------------------------------------------
    usuario = autenticar_usuario(
        username_normalizado,
        password,
    )

    if usuario is None:

        try:
            registrar_falha(
                acao=ACAO_LOGIN_FALHA,
                entidade="USUARIO",
                detalhes={
                    "username_informado": (username_normalizado),
                },
                usuario=(username_normalizado or None),
                commit=True,
            )

        except Exception:
            session.rollback()

        if request.is_json:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("INVALID_CREDENTIALS"),
                        "message": ("Usuário ou senha " "inválidos."),
                    }
                ),
                401,
            )

        flash(
            "Usuário ou senha inválidos.",
            "error",
        )

        return render_template("login.html"), 401

    # --------------------------------------------------------
    # LOGIN VÁLIDO
    # --------------------------------------------------------

    login_user(
        usuario,
        remember=False,
        fresh=True,
    )

    try:
        registrar_auditoria(
            acao=ACAO_LOGIN_SUCESSO,
            entidade="USUARIO",
            entidade_id=usuario.id,
            detalhes={
                "username": (usuario.username),
            },
            usuario=usuario,
            commit=True,
        )

    except Exception:
        session.rollback()

    precisa_trocar_senha = usuario.trocar_senha_proximo_login

    if request.is_json:

        return (
            jsonify(
                {
                    "success": True,
                    "message": ("Login realizado " "com sucesso."),
                    "data": {
                        "usuario": (serializar_usuario_logado(usuario)),
                        "trocar_senha": (precisa_trocar_senha),
                    },
                }
            ),
            200,
        )

    if precisa_trocar_senha:

        return redirect(url_for("auth.alterar_senha"))

    return redirect(obter_url_pos_login(next_url))


# ============================================================
# LOGOUT
# ============================================================


@auth_bp.route(
    "/logout",
    methods=[
        "GET",
        "POST",
    ],
)
@login_required
def logout():
    """
    Mantém GET por compatibilidade com o
    frontend antigo.

    No frontend novo utilizaremos POST.
    """

    usuario_id = current_user.id
    username = current_user.username

    try:
        registrar_auditoria(
            acao=ACAO_LOGOUT,
            entidade="USUARIO",
            entidade_id=usuario_id,
            detalhes={
                "username": username,
            },
            usuario=current_user,
            commit=True,
        )

    except Exception:
        session.rollback()

    logout_user()

    if request.is_json:

        return (
            jsonify(
                {
                    "success": True,
                    "message": ("Logout realizado " "com sucesso."),
                }
            ),
            200,
        )

    return redirect(url_for("auth.login"))


# ============================================================
# USUÁRIO ATUAL
# ============================================================


@auth_bp.route(
    "/api/auth/me",
    methods=["GET"],
)
@login_required
def usuario_atual():

    return jsonify(
        {
            "success": True,
            "data": {"usuario": (serializar_usuario_logado(current_user))},
        }
    )


# ============================================================
# ALTERAÇÃO DE SENHA
# ============================================================


@auth_bp.route(
    "/alterar-senha",
    methods=[
        "GET",
        "POST",
    ],
)
@password_change_allowed
def alterar_senha():

    if request.method == "GET":

        if is_api_request():

            return jsonify(
                {
                    "success": True,
                    "data": {
                        "troca_obrigatoria": (current_user.trocar_senha_proximo_login)
                    },
                }
            )

        return render_template("alterar_senha.html")

    # --------------------------------------------------------
    # DADOS
    # --------------------------------------------------------

    if request.is_json:

        dados = request.get_json(silent=True) or {}

        senha_atual = dados.get("senha_atual")

        nova_senha = dados.get("nova_senha")

        confirmar_senha = dados.get("confirmar_senha")

    else:

        senha_atual = request.form.get("senha_atual")

        nova_senha = request.form.get("nova_senha")

        confirmar_senha = request.form.get("confirmar_senha")

    # --------------------------------------------------------
    # VALIDAÇÃO SENHA ATUAL
    # --------------------------------------------------------

    if not current_user.check_password(senha_atual):

        mensagem = "A senha atual está incorreta."

        if request.is_json:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("INVALID_CURRENT_PASSWORD"),
                        "message": mensagem,
                    }
                ),
                400,
            )

        flash(
            mensagem,
            "error",
        )

        return render_template("alterar_senha.html"), 400

    # --------------------------------------------------------
    # CONFIRMAÇÃO
    # --------------------------------------------------------

    if nova_senha != confirmar_senha:

        mensagem = "A confirmação da nova senha " "não confere."

        if request.is_json:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("PASSWORD_CONFIRMATION_MISMATCH"),
                        "message": mensagem,
                    }
                ),
                400,
            )

        flash(
            mensagem,
            "error",
        )

        return render_template("alterar_senha.html"), 400

    # --------------------------------------------------------
    # REGRA DE SENHA
    # --------------------------------------------------------

    senha_valida, erro = validar_nova_senha(nova_senha)

    if not senha_valida:

        if request.is_json:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("INVALID_PASSWORD"),
                        "message": erro,
                    }
                ),
                400,
            )

        flash(
            erro,
            "error",
        )

        return render_template("alterar_senha.html"), 400

    # --------------------------------------------------------
    # NÃO PERMITE REPETIR A SENHA
    # --------------------------------------------------------

    if current_user.check_password(nova_senha):

        mensagem = "A nova senha deve ser " "diferente da senha atual."

        if request.is_json:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("PASSWORD_NOT_CHANGED"),
                        "message": mensagem,
                    }
                ),
                400,
            )

        flash(
            mensagem,
            "error",
        )

        return render_template("alterar_senha.html"), 400

    # --------------------------------------------------------
    # ALTERAÇÃO
    # --------------------------------------------------------

    try:

        current_user.set_password(nova_senha)

        current_user.trocar_senha_proximo_login = False

        current_user.atualizado_em = agora_utc()

        registrar_auditoria(
            acao=ACAO_SENHA_ALTERADA,
            entidade="USUARIO",
            entidade_id=current_user.id,
            detalhes={"username": (current_user.username)},
            usuario=current_user,
        )

        session.commit()

        # Torna a sessão novamente "fresh".
        confirm_login()

    except Exception:

        session.rollback()

        raise

    if request.is_json:

        return jsonify(
            {
                "success": True,
                "message": ("Senha alterada " "com sucesso."),
            }
        )

    flash(
        "Senha alterada com sucesso.",
        "success",
    )

    return redirect(url_for("main.index"))
