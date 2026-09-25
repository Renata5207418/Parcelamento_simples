import datetime
from decimal import Decimal
from pathlib import Path

from flask import has_request_context, request
from flask_login import current_user

from database.models import Auditoria, Usuario, session

# ============================================================
# AÇÕES DE AUDITORIA
# ============================================================
ACAO_LOGIN_SUCESSO = "LOGIN_SUCCESS"
ACAO_LOGIN_FALHA = "LOGIN_FAILED"
ACAO_LOGOUT = "LOGOUT"
ACAO_USUARIO_CRIADO = "USER_CREATED"
ACAO_USUARIO_ATUALIZADO = "USER_UPDATED"
ACAO_USUARIO_ATIVADO = "USER_ENABLED"
ACAO_USUARIO_DESATIVADO = "USER_DISABLED"
ACAO_SENHA_REDEFINIDA = "USER_PASSWORD_RESET"
ACAO_SENHA_ALTERADA = "USER_PASSWORD_CHANGED"
ACAO_CERTIFICADO_ENVIADO = "CERTIFICATE_UPLOADED"
ACAO_CERTIFICADO_SUBSTITUIDO = "CERTIFICATE_REPLACED"
ACAO_CERTIFICADO_ATIVADO = "CERTIFICATE_ENABLED"
ACAO_CERTIFICADO_DESATIVADO = "CERTIFICATE_DISABLED"
ACAO_CERTIFICADO_VALIDACAO_FALHOU = "CERTIFICATE_VALIDATION_FAILED"


# ============================================================
# CAMPOS QUE NUNCA DEVEM ENTRAR NA AUDITORIA
# ============================================================
CHAVES_SENSIVEIS = {
    "password",
    "password_hash",
    "senha",
    "senha_certificado",
    "senha_criptografada",
    "token",
    "access_token",
    "jwt_token",
    "refresh_token",
    "authorization",
    "consumer_key",
    "consumer_secret",
    "secret",
    "private_key",
    "chave_privada",
    "pkcs12_password",
}


# ============================================================
# NORMALIZAÇÃO
# ============================================================


def _chave_sensivel(chave):
    """
    Verifica se o nome de uma chave representa
    informação sensível.
    """
    if chave is None:
        return False

    chave_normalizada = str(chave).strip().lower()

    if chave_normalizada in CHAVES_SENSIVEIS:
        return True

    fragmentos_proibidos = (
        "password",
        "senha",
        "access_token",
        "jwt_token",
        "refresh_token",
        "consumer_secret",
        "authorization",
        "private_key",
        "chave_privada",
    )

    return any(fragmento in chave_normalizada for fragmento in fragmentos_proibidos)


def _normalizar_valor(valor):
    """
    Converte valores para formatos compatíveis
    com PostgreSQL JSON.
    """
    if valor is None:
        return None

    if isinstance(
        valor,
        (
            str,
            int,
            float,
            bool,
        ),
    ):
        return valor

    if isinstance(
        valor,
        Decimal,
    ):
        return str(valor)

    if isinstance(
        valor,
        (
            datetime.datetime,
            datetime.date,
            datetime.time,
        ),
    ):
        return valor.isoformat()

    if isinstance(
        valor,
        Path,
    ):
        return str(valor)

    if isinstance(
        valor,
        dict,
    ):
        return _sanitizar_detalhes(valor)

    if isinstance(
        valor,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [_normalizar_valor(item) for item in valor]

    return str(valor)


def _sanitizar_detalhes(detalhes):
    """
    Remove informações sensíveis do objeto
    enviado para auditoria.

    Essa função existe como uma segunda camada
    de proteção.

    Mesmo assim, o código chamador NÃO deve
    enviar senhas ou tokens para auditoria.
    """
    if detalhes is None:
        return None

    if not isinstance(
        detalhes,
        dict,
    ):
        return {"informacao": _normalizar_valor(detalhes)}

    resultado = {}

    for chave, valor in detalhes.items():

        chave_texto = str(chave)

        if _chave_sensivel(chave_texto):
            resultado[chave_texto] = "[REMOVIDO]"

            continue

        resultado[chave_texto] = _normalizar_valor(valor)

    return resultado


# ============================================================
# CONTEXTO HTTP
# ============================================================
def _obter_ip():
    """
    Obtém o IP apresentado pelo Flask.

    Não utiliza diretamente X-Forwarded-For,
    pois esse header pode ser falsificado.

    Caso futuramente a aplicação fique atrás
    de um proxy reverso confiável, configuraremos
    ProxyFix no app.py.
    """

    if not has_request_context():
        return None

    return request.remote_addr


def _obter_user_agent():
    """
    Obtém o User-Agent atual, quando existir
    contexto HTTP.
    """
    if not has_request_context():
        return None

    if not request.user_agent:
        return None

    valor = (request.user_agent.string or "").strip()
    return valor or None


# ============================================================
# RESOLUÇÃO DO USUÁRIO
# ============================================================
def _resolver_usuario(usuario=None):
    """
    Retorna:

        (usuario_id, username)

    Pode receber explicitamente um Usuario ou,
    quando dentro de uma requisição Flask,
    utiliza current_user.

    Ações de sistema também podem não possuir
    usuário associado.
    """
    usuario_resolvido = usuario

    if usuario_resolvido is None and has_request_context():
        try:
            if current_user and current_user.is_authenticated:
                usuario_resolvido = current_user

        except Exception:
            usuario_resolvido = None

    if usuario_resolvido is None:
        return (
            None,
            None,
        )

    if isinstance(
        usuario_resolvido,
        Usuario,
    ):
        return (
            usuario_resolvido.id,
            usuario_resolvido.username,
        )

    # Permite que, em alguns casos administrativos,
    # seja informado somente um username.
    if isinstance(
        usuario_resolvido,
        str,
    ):
        username = usuario_resolvido.strip().lower()

        return (
            None,
            username or None,
        )

    usuario_id = getattr(
        usuario_resolvido,
        "id",
        None,
    )

    username = getattr(
        usuario_resolvido,
        "username",
        None,
    )

    if username is not None:
        username = str(username).strip().lower()

    return (
        usuario_id,
        username or None,
    )


# ============================================================
# REGISTRO PRINCIPAL
# ============================================================
def registrar_auditoria(
    acao,
    entidade=None,
    entidade_id=None,
    detalhes=None,
    sucesso=True,
    usuario=None,
    ip=None,
    user_agent=None,
    commit=False,
):
    """
    Adiciona um registro de auditoria.

    Por padrão NÃO executa commit.

    Isso é proposital para permitir que a ação
    principal e sua auditoria façam parte da
    mesma transação.

    Exemplo:

        usuario = Usuario(...)
        session.add(usuario)
        session.flush()

        registrar_auditoria(
            acao=ACAO_USUARIO_CRIADO,
            entidade="USUARIO",
            entidade_id=usuario.id,
            detalhes={
                "username": usuario.username,
                "role": usuario.role,
            },
        )

        session.commit()


    Caso seja necessária uma auditoria independente:

        registrar_auditoria(
            acao="...",
            commit=True,
        )
    """

    if acao is None:
        raise ValueError("A ação da auditoria " "não foi informada.")

    acao = str(acao).strip().upper()

    if not acao:
        raise ValueError("A ação da auditoria " "não pode ser vazia.")

    if len(acao) > 100:
        raise ValueError(
            "A ação da auditoria " "não pode ultrapassar " "100 caracteres."
        )

    if entidade is not None:
        entidade = str(entidade).strip().upper()

        if not entidade:
            entidade = None

    if entidade_id is not None:
        entidade_id = str(entidade_id)

    usuario_id, username = _resolver_usuario(usuario)

    if ip is None:
        ip = _obter_ip()

    if user_agent is None:
        user_agent = _obter_user_agent()

    detalhes_limpos = _sanitizar_detalhes(detalhes)

    auditoria = Auditoria(
        usuario_id=usuario_id,
        username=username,
        acao=acao,
        entidade=entidade,
        entidade_id=entidade_id,
        sucesso=bool(sucesso),
        detalhes=detalhes_limpos,
        ip=ip,
        user_agent=user_agent,
    )

    session.add(auditoria)

    if commit:
        try:
            session.commit()

        except Exception:
            session.rollback()
            raise

    return auditoria


# ============================================================
# ATALHO PARA FALHAS
# ============================================================
def registrar_falha(
    acao,
    entidade=None,
    entidade_id=None,
    detalhes=None,
    usuario=None,
    commit=False,
):
    """
    Atalho para registrar ações que falharam.
    """
    return registrar_auditoria(
        acao=acao,
        entidade=entidade,
        entidade_id=entidade_id,
        detalhes=detalhes,
        sucesso=False,
        usuario=usuario,
        commit=commit,
    )
