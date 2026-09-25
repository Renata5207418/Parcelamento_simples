from routes.admin_routes import admin_bp
from routes.auth_routes import auth_bp
from routes.main_routes import main_bp
from routes.requisicao_routes import requisicoes_bp


def registrar_rotas(app):
    """
    Registra todos os Blueprints da aplicação.
    """
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(requisicoes_bp)
    app.register_blueprint(admin_bp)
