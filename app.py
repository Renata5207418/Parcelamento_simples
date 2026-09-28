import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from auth.auth_utils import init_auth
from database.models import init_db, shutdown_session
from routes import registrar_rotas

BASE_DIR = Path(__file__).resolve().parent
ARQUIVO_ENV_LOCAL = BASE_DIR / ".env"
ARQUIVO_ENV_RAIZ = BASE_DIR.parent / ".env"

if ARQUIVO_ENV_LOCAL.exists():
    load_dotenv(dotenv_path=ARQUIVO_ENV_LOCAL)
elif ARQUIVO_ENV_RAIZ.exists():
    load_dotenv(dotenv_path=ARQUIVO_ENV_RAIZ)


def obter_booleano_env(nome, padrao=False):
    """
    Converte uma variável do .env
    para boolean.

    Valores considerados verdadeiros:

        1
        true
        yes
        sim
        on
    """
    valor = os.getenv(nome)
    if valor is None:
        return padrao
    return valor.strip().lower() in {"1", "true", "yes", "sim", "on"}


def requisicao_api():
    """
    Identifica requisições voltadas para API.

    Usado principalmente pelos handlers
    globais de erro.
    """
    if request.path.startswith("/api/"):
        return True

    if request.is_json:
        return True

    melhor_resposta = request.accept_mimetypes.best
    return melhor_resposta == "application/json"


def create_app():
    """
    Cria e configura a aplicação Flask.
    """
    app = Flask(__name__, template_folder="templates", static_folder="static")
    secret_key = os.getenv("FLASK_SECRET_KEY", "").strip()
    if not secret_key:
        raise RuntimeError("FLASK_SECRET_KEY não foi configurada no arquivo .env.")
    app.secret_key = secret_key

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = obter_booleano_env(
        "SESSION_COOKIE_SECURE", False
    )
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
    app.config["REMEMBER_COOKIE_SECURE"] = obter_booleano_env(
        "SESSION_COOKIE_SECURE", False
    )

    try:
        max_upload_mb = int(os.getenv("MAX_UPLOAD_MB", "20"))

    except (TypeError, ValueError):
        max_upload_mb = 20
    if max_upload_mb <= 0:
        max_upload_mb = 20

    app.config["MAX_CONTENT_LENGTH"] = max_upload_mb * 1024 * 1024
    app.config["JSON_AS_ASCII"] = False

    init_auth(app)
    init_db()
    registrar_rotas(app)

    @app.teardown_appcontext
    def remover_sessao_sqlalchemy(exception=None):
        """
        Remove a sessão SQLAlchemy ligada
        à requisição/thread atual.
        """
        shutdown_session()

    @app.errorhandler(400)
    def erro_400(erro):
        if requisicao_api():
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("BAD_REQUEST"),
                        "message": ("Requisição inválida."),
                    }
                ),
                400,
            )

        return "Requisição inválida.", 400

    @app.errorhandler(403)
    def erro_403(erro):
        if requisicao_api():
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("PERMISSION_DENIED"),
                        "message": (
                            "Você não possui " "permissão para acessar " "este recurso."
                        ),
                    }
                ),
                403,
            )

        return "Acesso negado.", 403

    @app.errorhandler(404)
    def erro_404(erro):
        if requisicao_api():
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("NOT_FOUND"),
                        "message": ("Recurso não encontrado."),
                    }
                ),
                404,
            )

        return "Página não encontrada.", 404

    @app.errorhandler(413)
    def erro_413(erro):
        if requisicao_api():
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("FILE_TOO_LARGE"),
                        "message": (
                            "O arquivo enviado " "ultrapassa o limite " "permitido."
                        ),
                    }
                ),
                413,
            )

        return (
            "O arquivo enviado ultrapassa " "o limite permitido.",
            413,
        )

    @app.errorhandler(500)
    def erro_500(erro):
        if requisicao_api():
            return (
                jsonify(
                    {
                        "success": False,
                        "error": ("INTERNAL_SERVER_ERROR"),
                        "message": ("Ocorreu um erro interno " "no servidor."),
                    }
                ),
                500,
            )

        return "Erro interno do servidor.", 500

    return app


app = create_app()


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "127.0.0.1").strip()
    try:
        port = int(os.getenv("FLASK_PORT", "8500"))
    except (TypeError, ValueError):
        port = 8500
    debug = obter_booleano_env("FLASK_DEBUG", False)
    app.run(host=host, port=port, debug=debug)
