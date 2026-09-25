import datetime
import os
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import load_dotenv
from flask_login import UserMixin
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, scoped_session, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
ARQUIVO_ENV_LOCAL = BASE_DIR / ".env"
ARQUIVO_ENV_RAIZ = BASE_DIR.parent / ".env"

if ARQUIVO_ENV_LOCAL.exists():
    load_dotenv(dotenv_path=ARQUIVO_ENV_LOCAL)
elif ARQUIVO_ENV_RAIZ.exists():
    load_dotenv(dotenv_path=ARQUIVO_ENV_RAIZ)

ROLE_ADMIN = "ADMIN"
ROLE_USER = "USER"
ROLES_VALIDAS = {ROLE_ADMIN, ROLE_USER}
CERTIFICADO_MTLS = "MTLS"
CERTIFICADO_AUTOR = "AUTOR"
TIPOS_CERTIFICADO_VALIDOS = {CERTIFICADO_MTLS, CERTIFICADO_AUTOR}


def agora_utc():
    """Retorna datetime timezone-aware em UTC."""
    return datetime.datetime.now(datetime.timezone.utc)


def obter_database_url():
    """Monta a URL do PostgreSQL a partir do .env."""
    database_url = os.getenv("DATABASE_URL", "").strip()

    if database_url:
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace(
                "postgresql://", "postgresql+psycopg://", 1
            )
        return database_url

    host = os.getenv("POSTGRES_HOST", "").strip()
    port = os.getenv("POSTGRES_PORT", "5432").strip()
    dbname = os.getenv("POSTGRES_DB", "").strip()
    user = os.getenv("POSTGRES_USER", "").strip()
    password = os.getenv("POSTGRES_PASSWORD", "")

    obrigatorias = {
        "POSTGRES_HOST": host,
        "POSTGRES_DB": dbname,
        "POSTGRES_USER": user,
        "POSTGRES_PASSWORD": password,
    }

    ausentes = [nome for nome, valor in obrigatorias.items() if not valor]

    if ausentes:
        raise RuntimeError(
            f"Configuração PostgreSQL incompleta. Variáveis ausentes no .env: {', '.join(ausentes)}"
        )

    return f"postgresql+psycopg://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{dbname}"


NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)
Base = declarative_base(metadata=metadata)

DATABASE_URL = obter_database_url()
SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "sim",
    "on",
}

engine = create_engine(DATABASE_URL, pool_pre_ping=True, echo=SQLALCHEMY_ECHO)
Session = scoped_session(
    sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
)
session = Session


class Usuario(UserMixin, Base):
    __tablename__ = "usuarios"
    __table_args__ = (CheckConstraint("role IN ('ADMIN', 'USER')", name="role_valida"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(120), nullable=False, unique=True, index=True)
    nome = Column(String(200), nullable=False)
    password_hash = Column(String(512), nullable=False)
    role = Column(String(20), nullable=False, default=ROLE_USER, index=True)
    ativo = Column(Boolean, nullable=False, default=True, index=True)
    trocar_senha_proximo_login = Column(Boolean, nullable=False, default=False)
    criado_em = Column(DateTime(timezone=True), nullable=False, default=agora_utc)
    atualizado_em = Column(
        DateTime(timezone=True), nullable=False, default=agora_utc, onupdate=agora_utc
    )
    ultimo_login = Column(DateTime(timezone=True), nullable=True)
    senha_alterada_em = Column(DateTime(timezone=True), nullable=True)

    requisicoes = relationship(
        "Requisicao", back_populates="usuario", foreign_keys="Requisicao.usuario_id"
    )
    certificados_enviados = relationship(
        "Certificado",
        back_populates="usuario_upload",
        foreign_keys="Certificado.uploaded_by",
    )
    auditorias = relationship(
        "Auditoria", back_populates="usuario", foreign_keys="Auditoria.usuario_id"
    )

    @property
    def is_active(self):
        return bool(self.ativo)

    @property
    def is_admin(self):
        return self.role == ROLE_ADMIN

    def set_password(self, password):
        """Gera hash seguro da senha."""
        if not password:
            raise ValueError("A senha não pode ser vazia.")
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        self.senha_alterada_em = agora_utc()

    def check_password(self, password):
        """Confere a senha informada contra o hash."""
        if not password or not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<Usuario id={self.id} username={self.username!r} role={self.role!r} ativo={self.ativo}>"


class Requisicao(Base):
    __tablename__ = "requisicoes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    usuario_id = Column(
        Integer,
        ForeignKey("usuarios.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    contribuinte = Column(String(30), nullable=False, index=True)
    tipo_contribuinte = Column(Integer, nullable=False)
    id_sistema = Column(String(100), nullable=False)
    id_servico = Column(String(100), nullable=False)
    resposta_base64 = Column(Text, nullable=True)
    arquivo_pdf = Column(Text, nullable=True)
    pdf_sha256 = Column(String(64), nullable=True)
    pdf_tamanho_bytes = Column(Integer, nullable=True)
    data_envio = Column(
        DateTime(timezone=True), nullable=False, default=agora_utc, index=True
    )
    data_resposta = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(50), nullable=False, default="Pendente", index=True)
    response_message = Column(Text, nullable=True)

    usuario = relationship(
        "Usuario", back_populates="requisicoes", foreign_keys=[usuario_id]
    )

    def __repr__(self):
        return f"<Requisicao id={self.id} contribuinte={self.contribuinte!r} status={self.status!r}>"


Index(
    "ix_requisicoes_contribuinte_data_envio",
    Requisicao.contribuinte,
    Requisicao.data_envio,
)


class Certificado(Base):
    __tablename__ = "certificados"
    __table_args__ = (CheckConstraint("tipo IN ('MTLS', 'AUTOR')", name="tipo_valido"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    tipo = Column(String(20), nullable=False, index=True)
    nome_original = Column(String(255), nullable=False)
    arquivo_relativo = Column(Text, nullable=False)
    senha_criptografada = Column(Text, nullable=False)
    titular = Column(String(500), nullable=True)
    emissor = Column(String(500), nullable=True)
    cnpj = Column(String(20), nullable=True, index=True)
    serial_number = Column(String(255), nullable=True)
    fingerprint_sha256 = Column(String(64), nullable=False, index=True)
    valido_de = Column(DateTime(timezone=True), nullable=False)
    valido_ate = Column(DateTime(timezone=True), nullable=False, index=True)
    ativo = Column(Boolean, nullable=False, default=True, index=True)
    uploaded_by = Column(
        Integer,
        ForeignKey("usuarios.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    criado_em = Column(DateTime(timezone=True), nullable=False, default=agora_utc)
    desativado_em = Column(DateTime(timezone=True), nullable=True)

    usuario_upload = relationship(
        "Usuario", back_populates="certificados_enviados", foreign_keys=[uploaded_by]
    )

    @property
    def vencido(self):
        """Retorna True se o certificado estiver vencido."""
        return self.valido_ate <= agora_utc()

    @property
    def dias_para_vencer(self):
        """Quantidade de dias restantes até o vencimento."""
        return (self.valido_ate - agora_utc()).days

    def __repr__(self):
        return f"<Certificado id={self.id} tipo={self.tipo!r} ativo={self.ativo} valido_ate={self.valido_ate}>"


class Auditoria(Base):
    __tablename__ = "auditoria"

    id = Column(Integer, primary_key=True, autoincrement=True)
    usuario_id = Column(
        Integer,
        ForeignKey("usuarios.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    username = Column(String(120), nullable=True, index=True)
    acao = Column(String(100), nullable=False, index=True)
    entidade = Column(String(100), nullable=True, index=True)
    entidade_id = Column(String(100), nullable=True)
    sucesso = Column(Boolean, nullable=False, default=True)
    detalhes = Column(JSON, nullable=True)
    ip = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    criado_em = Column(
        DateTime(timezone=True), nullable=False, default=agora_utc, index=True
    )

    usuario = relationship(
        "Usuario", back_populates="auditorias", foreign_keys=[usuario_id]
    )

    def __repr__(self):
        return f"<Auditoria id={self.id} acao={self.acao!r} username={self.username!r}>"


def init_db():
    """Cria somente tabelas que ainda não existirem."""
    Base.metadata.create_all(bind=engine)


def testar_conexao():
    """Testa a conexão com PostgreSQL."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        print(f"Erro ao conectar ao PostgreSQL:\n{exc}")
        return False


def shutdown_session():
    """Remove a sessão SQLAlchemy associada à requisição/thread atual."""
    Session.remove()


@contextmanager
def session_scope():
    """Sessão segura para scripts administrativos e scripts de migração."""
    db = Session()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
        Session.remove()


if __name__ == "__main__":
    print("Testando conexão com PostgreSQL...")
    if not testar_conexao():
        raise SystemExit("Não foi possível conectar ao PostgreSQL.")

    print("Conexão com PostgreSQL estabelecida.")
    print("Criando/verificando tabelas...")
    init_db()
    print("Tabelas verificadas com sucesso.")
