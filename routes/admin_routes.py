from flask import Blueprint, jsonify, request
from flask_login import current_user
from sqlalchemy import func

from auth.audit_service import (
    ACAO_CERTIFICADO_ENVIADO,
    ACAO_CERTIFICADO_SUBSTITUIDO,
    ACAO_CERTIFICADO_VALIDACAO_FALHOU,
    ACAO_SENHA_REDEFINIDA,
    ACAO_USUARIO_ATIVADO,
    ACAO_USUARIO_ATUALIZADO,
    ACAO_USUARIO_CRIADO,
    ACAO_USUARIO_DESATIVADO,
    registrar_auditoria,
    registrar_falha,
)
from auth.auth_utils import (
    admin_required,
    normalizar_username,
    validar_nova_senha,
    validar_role,
)
from auth.certificate_service import (
    CertificateServiceError,
    cadastrar_certificado,
    listar_certificados,
    remover_arquivo_certificado,
    serializar_certificado,
)
from database.models import (
    ROLE_ADMIN,
    ROLE_USER,
    Auditoria,
    Certificado,
    Usuario,
    agora_utc,
    session,
)

# ============================================================
# BLUEPRINT
# ============================================================
admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

# ============================================================
# CONFIGURAÇÕES
# ============================================================
MAX_USUARIOS_POR_PAGINA = 100
MAX_AUDITORIA_POR_PAGINA = 100


# ============================================================
# RESPOSTAS
# ============================================================
def resposta_ok(
    data=None,
    message=None,
    status_code=200,
):
    """
    Padroniza respostas de sucesso.
    """
    payload = {"success": True}
    if message is not None:
        payload["message"] = message
    if data is not None:
        payload["data"] = data
    return jsonify(payload), status_code


def resposta_erro(message, error="BAD_REQUEST", status_code=400, detalhes=None):
    """
    Padroniza respostas de erro.

    Não utilizar detalhes para enviar exceções
    contendo senhas, tokens ou segredos.
    """
    payload = {"success": False, "error": error, "message": message}
    if detalhes is not None:
        payload["details"] = detalhes
    return jsonify(payload), status_code


# ============================================================
# HELPERS - JSON
# ============================================================
def obter_json():
    """
    Obtém JSON da requisição de maneira segura.
    """
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        return {}
    return dados


def converter_booleano(valor, campo="valor"):
    """
    Converte valores comuns para boolean.

    Aceita:
        true / false
        1 / 0
        sim / nao
        yes / no
        on / off
    """
    if isinstance(valor, bool):
        return valor
    if isinstance(valor, int):
        if valor == 1:
            return True
        if valor == 0:
            return False
    if isinstance(valor, str):
        normalizado = valor.strip().lower()
        if normalizado in {"true", "1", "sim", "yes", "on"}:
            return True
        if normalizado in {"false", "0", "nao", "não", "no", "off"}:
            return False
    raise ValueError(f"Campo '{campo}' deve ser " "verdadeiro ou falso.")


# ============================================================
# SERIALIZAÇÃO - USUÁRIO
# ============================================================
def serializar_usuario(usuario):
    """
    Retorna somente informações seguras.

    Nunca retorna password_hash.
    """
    return {
        "id": usuario.id,
        "username": usuario.username,
        "nome": usuario.nome,
        "role": usuario.role,
        "ativo": usuario.ativo,
        "trocar_senha_proximo_login": (usuario.trocar_senha_proximo_login),
        "criado_em": (usuario.criado_em.isoformat() if usuario.criado_em else None),
        "atualizado_em": (
            usuario.atualizado_em.isoformat() if usuario.atualizado_em else None
        ),
        "ultimo_login": (
            usuario.ultimo_login.isoformat() if usuario.ultimo_login else None
        ),
        "senha_alterada_em": (
            usuario.senha_alterada_em.isoformat() if usuario.senha_alterada_em else None
        ),
    }


# ============================================================
# SERIALIZAÇÃO - AUDITORIA
# ============================================================
def serializar_auditoria(registro):
    """
    Serialização segura do log de auditoria.
    """
    return {
        "id": registro.id,
        "usuario_id": registro.usuario_id,
        "username": registro.username,
        "acao": registro.acao,
        "entidade": registro.entidade,
        "entidade_id": registro.entidade_id,
        "sucesso": registro.sucesso,
        "detalhes": registro.detalhes,
        "ip": registro.ip,
        "user_agent": registro.user_agent,
        "criado_em": (registro.criado_em.isoformat() if registro.criado_em else None),
    }


# ============================================================
# ADMINISTRADORES
# ============================================================
def contar_admins_ativos():
    """
    Quantidade de administradores ativos.
    """
    return (
        session.query(func.count(Usuario.id))
        .filter(
            Usuario.role == ROLE_ADMIN,
            Usuario.ativo.is_(True),
        )
        .scalar()
        or 0
    )


def validar_alteracao_admin(usuario, nova_role=None, novo_ativo=None):
    """
    Impede que a administração do sistema seja
    perdida acidentalmente.

    Regras:

    - usuário não pode desativar a própria conta;
    - usuário não pode remover seu próprio ADMIN;
    - último ADMIN ativo não pode ser desativado;
    - último ADMIN ativo não pode virar USER.
    """
    eh_proprio_usuario = current_user.id == usuario.id
    if novo_ativo is False and eh_proprio_usuario:
        raise ValueError("Você não pode desativar " "o próprio usuário.")
    if nova_role is not None and nova_role != ROLE_ADMIN and eh_proprio_usuario:
        raise ValueError("Você não pode remover " "o próprio perfil ADMIN.")
    removendo_admin = (
        usuario.role == ROLE_ADMIN
        and ((nova_role is not None and nova_role != ROLE_ADMIN) or novo_ativo is False)
        and usuario.ativo
    )
    if removendo_admin and contar_admins_ativos() <= 1:
        raise ValueError(
            "Não é possível remover ou " "desativar o último " "administrador ativo."
        )


# ============================================================
# USUÁRIOS - LISTAGEM
# ============================================================
@admin_bp.route("/usuarios", methods=["GET"])
@admin_required
def listar_usuarios():
    """
    Lista usuários cadastrados.
    """
    busca = request.args.get("busca", "").strip()
    role = request.args.get("role", "").strip().upper()
    ativo = request.args.get("ativo")
    try:
        pagina = max(int(request.args.get("pagina", 1)), 1)
        por_pagina = int(request.args.get("por_pagina", 50))
        por_pagina = max(1, min(por_pagina, MAX_USUARIOS_POR_PAGINA))
    except ValueError:
        return resposta_erro("Paginação inválida.", error="INVALID_PAGINATION")
    query = session.query(Usuario)
    if busca:
        termo = f"%{busca}%"
        query = query.filter(
            (Usuario.username.ilike(termo)) | (Usuario.nome.ilike(termo))
        )
    if role:
        try:
            role = validar_role(role)
        except ValueError as exc:
            return resposta_erro(str(exc), error="INVALID_ROLE")
        query = query.filter(Usuario.role == role)
    if ativo is not None:
        try:
            ativo_bool = converter_booleano(
                ativo,
                "ativo",
            )
        except ValueError as exc:
            return resposta_erro(str(exc), error="INVALID_ACTIVE_VALUE")
        query = query.filter(Usuario.ativo.is_(ativo_bool))
    total = query.count()
    usuarios = (
        query.order_by(
            Usuario.nome.asc(),
            Usuario.username.asc(),
        )
        .offset((pagina - 1) * por_pagina)
        .limit(por_pagina)
        .all()
    )
    return resposta_ok(
        {
            "usuarios": [serializar_usuario(usuario) for usuario in usuarios],
            "paginacao": {
                "pagina": pagina,
                "por_pagina": (por_pagina),
                "total": total,
                "total_paginas": ((total + por_pagina - 1) // por_pagina),
            },
        }
    )


# ============================================================
# USUÁRIOS - CRIAÇÃO
# ============================================================


@admin_bp.route("/usuarios", methods=["POST"])
@admin_required
def criar_usuario():
    """
    Cria um novo usuário.

    JSON esperado:

    {
        "username": "...",
        "nome": "...",
        "password": "...",
        "role": "USER",
        "trocar_senha_proximo_login": true
    }
    """
    dados = obter_json()
    username = normalizar_username(dados.get("username"))
    nome = str(dados.get("nome", "")).strip()
    password = dados.get("password")
    role = dados.get("role", ROLE_USER)
    trocar_senha = dados.get("trocar_senha_proximo_login", True)

    # --------------------------------------------------------
    # VALIDAÇÕES
    # --------------------------------------------------------
    if not username:
        return resposta_erro("Username é obrigatório.", error="USERNAME_REQUIRED")
    if len(username) > 120:
        return resposta_erro(
            "Username não pode ultrapassar " "120 caracteres.",
            error="USERNAME_TOO_LONG",
        )
    if not nome:
        return resposta_erro("Nome é obrigatório.", error="NAME_REQUIRED")
    if len(nome) > 200:
        return resposta_erro(
            "Nome não pode ultrapassar " "200 caracteres.", error="NAME_TOO_LONG"
        )
    try:
        role = validar_role(role)
    except ValueError as exc:
        return resposta_erro(str(exc), error="INVALID_ROLE")
    senha_valida, erro_senha = validar_nova_senha(password)
    if not senha_valida:
        return resposta_erro(erro_senha, error="INVALID_PASSWORD")
    try:
        trocar_senha = converter_booleano(
            trocar_senha,
            "trocar_senha_proximo_login",
        )
    except ValueError as exc:
        return resposta_erro(str(exc), error="INVALID_PASSWORD_CHANGE_VALUE")
    existente = session.query(Usuario).filter(Usuario.username == username).first()
    if existente is not None:
        return resposta_erro(
            "Já existe um usuário " "com esse username.",
            error="USERNAME_ALREADY_EXISTS",
            status_code=409,
        )

    # --------------------------------------------------------
    # CRIAÇÃO
    # --------------------------------------------------------
    try:
        usuario = Usuario(
            username=username,
            nome=nome,
            role=role,
            ativo=True,
            trocar_senha_proximo_login=trocar_senha,
        )
        usuario.set_password(password)
        session.add(usuario)
        # Obtém o ID antes do commit.
        session.flush()
        registrar_auditoria(
            acao=ACAO_USUARIO_CRIADO,
            entidade="USUARIO",
            entidade_id=usuario.id,
            detalhes={
                "username": (usuario.username),
                "nome": usuario.nome,
                "role": usuario.role,
                "ativo": usuario.ativo,
                "trocar_senha_proximo_login": (usuario.trocar_senha_proximo_login),
            },
        )
        session.commit()
        return resposta_ok(
            serializar_usuario(usuario),
            message=("Usuário criado com sucesso."),
            status_code=201,
        )
    except Exception:
        session.rollback()
        raise


# ============================================================
# USUÁRIOS - ALTERAÇÃO
# ============================================================
@admin_bp.route(
    "/usuarios/<int:usuario_id>",
    methods=["PATCH"],
)
@admin_required
def atualizar_usuario(usuario_id):
    """
    Altera:

        username
        nome
        role
        ativo
        trocar_senha_proximo_login
    """
    usuario = session.get(Usuario, usuario_id)
    if usuario is None:
        return resposta_erro(
            "Usuário não encontrado.", error="USER_NOT_FOUND", status_code=404
        )
    dados = obter_json()
    alteracoes = {}
    novo_username = None
    novo_nome = None
    nova_role = None
    novo_ativo = None
    nova_troca_senha = None

    # --------------------------------------------------------
    # USERNAME
    # --------------------------------------------------------
    if "username" in dados:
        novo_username = normalizar_username(dados.get("username"))
        if not novo_username:
            return resposta_erro(
                "Username não pode ser vazio.", error="INVALID_USERNAME"
            )
        if len(novo_username) > 120:
            return resposta_erro(
                "Username não pode ultrapassar " "120 caracteres.",
                error="USERNAME_TOO_LONG",
            )
        conflito = (
            session.query(Usuario)
            .filter(
                Usuario.username == novo_username,
                Usuario.id != usuario.id,
            )
            .first()
        )
        if conflito is not None:
            return resposta_erro(
                "Já existe outro usuário " "com esse username.",
                error="USERNAME_ALREADY_EXISTS",
                status_code=409,
            )

    # --------------------------------------------------------
    # NOME
    # --------------------------------------------------------
    if "nome" in dados:
        novo_nome = str(dados.get("nome", "")).strip()
        if not novo_nome:
            return resposta_erro("Nome não pode ser vazio.", error="INVALID_NAME")
        if len(novo_nome) > 200:
            return resposta_erro(
                "Nome não pode ultrapassar " "200 caracteres.", error="NAME_TOO_LONG"
            )

    # --------------------------------------------------------
    # ROLE
    # --------------------------------------------------------
    if "role" in dados:
        try:
            nova_role = validar_role(dados.get("role"))
        except ValueError as exc:
            return resposta_erro(str(exc), error="INVALID_ROLE")

    # --------------------------------------------------------
    # ATIVO
    # --------------------------------------------------------
    if "ativo" in dados:
        try:
            novo_ativo = converter_booleano(
                dados.get("ativo"),
                "ativo",
            )
        except ValueError as exc:
            return resposta_erro(str(exc), error="INVALID_ACTIVE_VALUE")

    # --------------------------------------------------------
    # TROCA OBRIGATÓRIA
    # --------------------------------------------------------
    if "trocar_senha_proximo_login" in dados:
        try:
            nova_troca_senha = converter_booleano(
                dados.get("trocar_senha_proximo_login"),
                ("trocar_senha_" "proximo_login"),
            )
        except ValueError as exc:
            return resposta_erro(str(exc), error="INVALID_PASSWORD_CHANGE_VALUE")
    try:
        validar_alteracao_admin(usuario, nova_role=nova_role, novo_ativo=novo_ativo)
    except ValueError as exc:
        return resposta_erro(str(exc), error="ADMIN_PROTECTION", status_code=409)

    # --------------------------------------------------------
    # APLICA ALTERAÇÕES
    # --------------------------------------------------------
    try:
        if novo_username is not None and novo_username != usuario.username:
            alteracoes["username"] = {
                "antes": usuario.username,
                "depois": novo_username,
            }
            usuario.username = novo_username
        if novo_nome is not None and novo_nome != usuario.nome:
            alteracoes["nome"] = {"antes": usuario.nome, "depois": novo_nome}
            usuario.nome = novo_nome
        if nova_role is not None and nova_role != usuario.role:
            alteracoes["role"] = {"antes": usuario.role, "depois": nova_role}
            usuario.role = nova_role
        if novo_ativo is not None and novo_ativo != usuario.ativo:
            alteracoes["ativo"] = {"antes": usuario.ativo, "depois": novo_ativo}
            usuario.ativo = novo_ativo
        if (
            nova_troca_senha is not None
            and nova_troca_senha != usuario.trocar_senha_proximo_login
        ):
            alteracoes["trocar_senha_proximo_login"] = {
                "antes": (usuario.trocar_senha_proximo_login),
                "depois": (nova_troca_senha),
            }
            usuario.trocar_senha_proximo_login = nova_troca_senha
        if not alteracoes:
            return resposta_ok(
                serializar_usuario(usuario), message=("Nenhuma alteração necessária.")
            )
        usuario.atualizado_em = agora_utc()

        # ----------------------------------------------------
        # DEFINE AÇÃO PRINCIPAL
        # ----------------------------------------------------

        if "ativo" in alteracoes and alteracoes["ativo"]["depois"] is False:
            acao = ACAO_USUARIO_DESATIVADO
        elif "ativo" in alteracoes and alteracoes["ativo"]["depois"] is True:
            acao = ACAO_USUARIO_ATIVADO
        else:
            acao = ACAO_USUARIO_ATUALIZADO
        registrar_auditoria(
            acao=acao,
            entidade="USUARIO",
            entidade_id=usuario.id,
            detalhes={
                "usuario_afetado": (usuario.username),
                "alteracoes": alteracoes,
            },
        )
        session.commit()
        return resposta_ok(
            serializar_usuario(usuario), message=("Usuário atualizado com sucesso.")
        )
    except Exception:
        session.rollback()
        raise


# ============================================================
# USUÁRIOS - REDEFINIÇÃO DE SENHA
# ============================================================
@admin_bp.route("/usuarios/" "<int:usuario_id>/" "redefinir-senha", methods=["POST"])
@admin_required
def redefinir_senha_usuario(usuario_id):
    """
    Redefine a senha de um usuário.

    JSON:

    {
        "password": "...",
        "trocar_senha_proximo_login": true
    }
    """
    usuario = session.get(Usuario, usuario_id)
    if usuario is None:
        return resposta_erro(
            "Usuário não encontrado.", error="USER_NOT_FOUND", status_code=404
        )
    dados = obter_json()
    password = dados.get("password")
    trocar_senha = dados.get("trocar_senha_proximo_login", True)
    senha_valida, erro_senha = validar_nova_senha(password)
    if not senha_valida:
        return resposta_erro(erro_senha, error="INVALID_PASSWORD")
    try:
        trocar_senha = converter_booleano(
            trocar_senha,
            "trocar_senha_proximo_login",
        )
    except ValueError as exc:
        return resposta_erro(str(exc), error="INVALID_PASSWORD_CHANGE_VALUE")
    try:
        usuario.set_password(password)
        usuario.trocar_senha_proximo_login = trocar_senha
        usuario.atualizado_em = agora_utc()
        registrar_auditoria(
            acao=ACAO_SENHA_REDEFINIDA,
            entidade="USUARIO",
            entidade_id=usuario.id,
            detalhes={
                "usuario_afetado": (usuario.username),
                "trocar_senha_proximo_login": (trocar_senha),
            },
        )
        session.commit()
        return resposta_ok(
            {
                "usuario_id": usuario.id,
                "username": (usuario.username),
                "trocar_senha_proximo_login": (usuario.trocar_senha_proximo_login),
            },
            message=("Senha redefinida com sucesso."),
        )
    except Exception:
        session.rollback()
        raise


# ============================================================
# CERTIFICADOS - LISTAGEM
# ============================================================
@admin_bp.route("/certificados", methods=["GET"])
@admin_required
def consultar_certificados():
    """
    Lista os certificados cadastrados.

    Parâmetros opcionais:

        tipo=MTLS
        tipo=AUTOR

        somente_ativos=true
    """
    tipo = request.args.get("tipo")
    somente_ativos = request.args.get("somente_ativos", "false")
    try:
        somente_ativos = converter_booleano(
            somente_ativos,
            "somente_ativos",
        )
        certificados = listar_certificados(
            tipo=tipo,
            somente_ativos=somente_ativos,
        )
    except CertificateServiceError as exc:
        return resposta_erro(str(exc), error="CERTIFICATE_ERROR")
    except ValueError as exc:
        return resposta_erro(str(exc), error="INVALID_VALUE")
    return resposta_ok(
        {
            "certificados": [
                serializar_certificado(certificado) for certificado in certificados
            ]
        }
    )


# ============================================================
# CERTIFICADOS - UPLOAD
# ============================================================
@admin_bp.route("/certificados", methods=["POST"])
@admin_required
def enviar_certificado():
    """
    Upload de certificado.

    multipart/form-data:

        tipo=MTLS ou AUTOR
        senha=...
        arquivo=<arquivo .pfx/.p12>
    """
    tipo = request.form.get("tipo", "").strip().upper()
    senha = request.form.get("senha")
    arquivo = request.files.get("arquivo")
    if not tipo:
        return resposta_erro(
            "Tipo do certificado " "não informado.", error="CERTIFICATE_TYPE_REQUIRED"
        )
    if arquivo is None:
        return resposta_erro(
            "Arquivo do certificado " "não informado.",
            error="CERTIFICATE_FILE_REQUIRED",
        )
    if not arquivo.filename:
        return resposta_erro(
            "Nenhum arquivo foi selecionado.", error="CERTIFICATE_FILE_REQUIRED"
        )
    if senha is None:
        return resposta_erro(
            "Senha do certificado " "não informada.",
            error="CERTIFICATE_PASSWORD_REQUIRED",
        )
    try:
        conteudo = arquivo.read()
    except Exception:
        return resposta_erro(
            "Não foi possível ler " "o arquivo enviado.", error="CERTIFICATE_READ_ERROR"
        )
    novo_certificado = None
    anterior_ativo = (
        session.query(Certificado)
        .filter(
            Certificado.tipo == tipo,
            Certificado.ativo.is_(True),
        )
        .order_by(Certificado.criado_em.desc())
        .first()
    )
    try:
        novo_certificado = cadastrar_certificado(
            tipo=tipo,
            nome_original=arquivo.filename,
            conteudo=conteudo,
            senha=senha,
            uploaded_by=current_user.id,
        )
        if anterior_ativo is None:
            acao = ACAO_CERTIFICADO_ENVIADO
        else:
            acao = ACAO_CERTIFICADO_SUBSTITUIDO
        registrar_auditoria(
            acao=acao,
            entidade="CERTIFICADO",
            entidade_id=novo_certificado.id,
            detalhes={
                "tipo": (novo_certificado.tipo),
                "titular": (novo_certificado.titular),
                "cnpj": (novo_certificado.cnpj),
                "valido_de": (novo_certificado.valido_de),
                "valido_ate": (novo_certificado.valido_ate),
                "fingerprint_sha256": (novo_certificado.fingerprint_sha256),
                "substituiu_certificado_id": (
                    anterior_ativo.id if anterior_ativo else None
                ),
            },
        )
        session.commit()
        return resposta_ok(
            serializar_certificado(novo_certificado),
            message=(
                "Certificado atualizado " "com sucesso."
                if anterior_ativo
                else "Certificado cadastrado " "com sucesso."
            ),
            status_code=201,
        )
    except CertificateServiceError as exc:
        session.rollback()
        if novo_certificado is not None:
            remover_arquivo_certificado(novo_certificado)
        try:
            registrar_falha(
                acao=ACAO_CERTIFICADO_VALIDACAO_FALHOU,
                entidade="CERTIFICADO",
                detalhes={
                    "tipo": tipo,
                    "nome_arquivo": (arquivo.filename),
                    "motivo": (exc.__class__.__name__),
                },
                commit=True,
            )
        except Exception:
            session.rollback()
        return resposta_erro(str(exc), error=exc.__class__.__name__)
    except Exception:
        session.rollback()
        if novo_certificado is not None:
            remover_arquivo_certificado(novo_certificado)
        raise


# ============================================================
# AUDITORIA - LISTAGEM
# ============================================================
@admin_bp.route("/auditoria", methods=["GET"])
@admin_required
def listar_auditoria():
    """
    Lista o histórico administrativo.
    Filtros:

        acao=
        username=
        entidade=
        sucesso=true/false
        pagina=
        por_pagina=
    """
    acao = request.args.get("acao", "").strip().upper()
    username = request.args.get("username", "").strip().lower()
    entidade = request.args.get("entidade", "").strip().upper()
    sucesso = request.args.get("sucesso")
    try:
        pagina = max(int(request.args.get("pagina", 1)), 1)
        por_pagina = int(request.args.get("por_pagina", 50))
        por_pagina = max(1, min(por_pagina, MAX_AUDITORIA_POR_PAGINA))
    except ValueError:
        return resposta_erro("Paginação inválida.", error="INVALID_PAGINATION")
    query = session.query(Auditoria)
    if acao:
        query = query.filter(Auditoria.acao == acao)
    if username:
        query = query.filter(Auditoria.username == username)
    if entidade:
        query = query.filter(Auditoria.entidade == entidade)
    if sucesso is not None:
        try:
            sucesso_bool = converter_booleano(
                sucesso,
                "sucesso",
            )
        except ValueError as exc:
            return resposta_erro(str(exc), error="INVALID_SUCCESS_VALUE")
        query = query.filter(Auditoria.sucesso.is_(sucesso_bool))
    total = query.count()
    registros = (
        query.order_by(
            Auditoria.criado_em.desc(),
            Auditoria.id.desc(),
        )
        .offset((pagina - 1) * por_pagina)
        .limit(por_pagina)
        .all()
    )
    return resposta_ok(
        {
            "registros": [serializar_auditoria(registro) for registro in registros],
            "paginacao": {
                "pagina": pagina,
                "por_pagina": (por_pagina),
                "total": total,
                "total_paginas": ((total + por_pagina - 1) // por_pagina),
            },
        }
    )
