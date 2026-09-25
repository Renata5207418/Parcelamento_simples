import datetime
import os
import re
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID
from werkzeug.utils import secure_filename

from database.models import (
    CERTIFICADO_AUTOR,
    CERTIFICADO_MTLS,
    TIPOS_CERTIFICADO_VALIDOS,
    Certificado,
    agora_utc,
    session,
)

EXTENSOES_PERMITIDAS = {
    ".pfx",
    ".p12",
}
TAMANHO_MAXIMO_CERTIFICADO = 10 * 1024 * 1024
OID_CNPJ_PJ = "2.16.76.1.3.3"


class CertificateServiceError(Exception):
    """
    Exceção base do gerenciamento de certificados.
    """


class CertificadoConfiguracaoError(CertificateServiceError):
    pass


class CertificadoInvalidoError(CertificateServiceError):
    pass


class CertificadoSenhaInvalidaError(CertificateServiceError):
    pass


class CertificadoVencidoError(CertificateServiceError):
    pass


class CertificadoNaoVigenteError(CertificateServiceError):
    pass


class CertificadoNaoEncontradoError(CertificateServiceError):
    pass


class CertificadoDuplicadoError(CertificateServiceError):
    pass


class CertificadoArquivoNaoEncontradoError(CertificateServiceError):
    pass


class CertificadoCriptografiaError(CertificateServiceError):
    pass


def obter_diretorio_certificados():
    """
    Obtém a pasta raiz dos certificados.

    A configuração deve existir no .env:

        CERTIFICATE_STORAGE_DIR=...

    Pode ser caminho absoluto ou relativo à raiz
    do projeto.
    """
    valor = os.getenv("CERTIFICATE_STORAGE_DIR", "").strip()

    if not valor:
        raise CertificadoConfiguracaoError(
            "CERTIFICATE_STORAGE_DIR " "não foi configurado no .env."
        )

    caminho = Path(valor).expanduser()

    if not caminho.is_absolute():
        caminho = Path(__file__).resolve().parent / caminho

    caminho = caminho.resolve()

    caminho.mkdir(
        parents=True,
        exist_ok=True,
    )

    _proteger_diretorio(caminho)

    return caminho


def _proteger_diretorio(caminho):
    """
    Em Linux/macOS tenta restringir a pasta
    ao usuário do processo.

    No Windows, chmod possui comportamento
    diferente; por isso a aplicação não depende
    dessa proteção para funcionar.
    """
    try:
        if os.name != "nt":
            os.chmod(
                caminho,
                0o700,
            )
    except OSError:
        pass


def _proteger_arquivo(caminho):
    """
    Em sistemas POSIX restringe o arquivo
    ao usuário do processo.
    """
    try:
        if os.name != "nt":
            os.chmod(
                caminho,
                0o600,
            )
    except OSError:
        pass


def obter_fernet():
    """
    Retorna o objeto Fernet utilizado para
    proteger as senhas dos certificados.

    A chave deve existir apenas no .env:

        CERTIFICATE_ENCRYPTION_KEY=...
    """
    chave = os.getenv("CERTIFICATE_ENCRYPTION_KEY", "").strip()

    if not chave:
        raise CertificadoConfiguracaoError(
            "CERTIFICATE_ENCRYPTION_KEY " "não foi configurada no .env."
        )

    try:
        return Fernet(chave.encode("utf-8"))

    except Exception as exc:
        raise CertificadoConfiguracaoError(
            "CERTIFICATE_ENCRYPTION_KEY " "é inválida."
        ) from exc


def gerar_chave_criptografia():
    """
    Gera uma chave Fernet nova.

    Deve ser utilizada apenas durante a
    configuração inicial do sistema.

    Exemplo:

        from certificate_service import gerar_chave_criptografia
        print(gerar_chave_criptografia())

    Depois, copie o resultado para o .env.
    """
    return Fernet.generate_key().decode("utf-8")


def criptografar_senha(senha):
    """
    Criptografa a senha do PFX antes de salvar
    no PostgreSQL.
    """
    if senha is None:
        raise CertificadoCriptografiaError("Senha do certificado não informada.")

    try:
        valor = str(senha).encode("utf-8")

        return obter_fernet().encrypt(valor).decode("utf-8")

    except CertificateServiceError:
        raise

    except Exception as exc:
        raise CertificadoCriptografiaError(
            "Não foi possível criptografar " "a senha do certificado."
        ) from exc


def descriptografar_senha(senha_criptografada):
    """
    Recupera internamente a senha necessária
    para abrir o PFX.

    Essa função nunca deve ser exposta
    diretamente pelo frontend.
    """
    if not senha_criptografada:
        raise CertificadoCriptografiaError(
            "O certificado não possui senha " "criptografada cadastrada."
        )

    try:
        return (
            obter_fernet().decrypt(senha_criptografada.encode("utf-8")).decode("utf-8")
        )

    except InvalidToken as exc:
        raise CertificadoCriptografiaError(
            "Não foi possível descriptografar "
            "a senha do certificado. "
            "Verifique a chave de criptografia."
        ) from exc

    except CertificateServiceError:
        raise

    except Exception as exc:
        raise CertificadoCriptografiaError(
            "Erro ao descriptografar a senha " "do certificado."
        ) from exc


def validar_tipo_certificado(tipo):
    """
    Normaliza e valida:

        MTLS
        AUTOR
    """
    if tipo is None:
        raise CertificadoInvalidoError("Tipo do certificado não informado.")

    tipo = str(tipo).strip().upper()

    if tipo not in TIPOS_CERTIFICADO_VALIDOS:
        raise CertificadoInvalidoError(
            "Tipo de certificado inválido. "
            f"Permitidos: "
            f"{', '.join(sorted(TIPOS_CERTIFICADO_VALIDOS))}."
        )

    return tipo


def _normalizar_datetime_utc(valor):
    """
    Garante datetime timezone-aware em UTC.
    """
    if valor is None:
        return None

    if valor.tzinfo is None:
        return valor.replace(tzinfo=datetime.timezone.utc)

    return valor.astimezone(datetime.timezone.utc)


def _validade_certificado(certificado):
    """
    Compatibilidade com diferentes versões
    da biblioteca cryptography.
    """
    try:
        valido_de = certificado.not_valid_before_utc

        valido_ate = certificado.not_valid_after_utc

    except AttributeError:

        valido_de = certificado.not_valid_before

        valido_ate = certificado.not_valid_after

    return (
        _normalizar_datetime_utc(valido_de),
        _normalizar_datetime_utc(valido_ate),
    )


def _extrair_cnpj_texto(valor):
    """
    Procura uma sequência de 14 dígitos em texto.
    """
    if valor is None:
        return None

    numeros = re.findall(r"\d", str(valor))

    sequencia = "".join(numeros)

    if len(sequencia) == 14:
        return sequencia

    encontrados = re.findall(r"(?<!\d)\d{14}(?!\d)", str(valor))

    if encontrados:
        return encontrados[0]

    return None


def _extrair_cnpj_bytes(valor):
    """
    Procura CNPJ dentro de valores ASN.1/DER
    presentes em extensões OtherName.

    O DER normalmente contém os próprios
    caracteres numéricos, mesmo com bytes
    adicionais de identificação do tipo.
    """
    if not valor:
        return None

    encontrados = re.findall(rb"\d{14}", valor)

    if not encontrados:
        return None

    try:
        return encontrados[0].decode("ascii")

    except UnicodeDecodeError:
        return None


def extrair_cnpj_certificado(certificado):
    """
    Tenta localizar CNPJ em diferentes campos
    utilizados por certificados ICP-Brasil.

    Ordem:

    1. Subject serialNumber
    2. OID específico de CNPJ em Subject
    3. Subject Alternative Name / OtherName
    """
    try:
        atributos = certificado.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)

        for atributo in atributos:

            cnpj = _extrair_cnpj_texto(atributo.value)

            if cnpj:
                return cnpj

    except Exception:
        pass

    try:
        oid_cnpj = x509.ObjectIdentifier(OID_CNPJ_PJ)

        atributos = certificado.subject.get_attributes_for_oid(oid_cnpj)

        for atributo in atributos:

            cnpj = _extrair_cnpj_texto(atributo.value)

            if cnpj:
                return cnpj

    except Exception:
        pass

    try:
        extensao = certificado.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        valores = extensao.value.get_values_for_type(x509.OtherName)

        for other_name in valores:

            if other_name.type_id.dotted_string != OID_CNPJ_PJ:
                continue

            cnpj = _extrair_cnpj_bytes(other_name.value)

            if cnpj:
                return cnpj

    except x509.ExtensionNotFound:
        pass

    except Exception:
        pass

    return None


def _obter_common_name(nome_x509):
    """
    Retorna Common Name quando disponível.
    """
    try:
        atributos = nome_x509.get_attributes_for_oid(NameOID.COMMON_NAME)

        if atributos:
            return atributos[0].value

    except Exception:
        pass

    try:
        return nome_x509.rfc4514_string()

    except Exception:
        return None


def validar_certificado_pfx(conteudo, senha):
    """
    Valida um arquivo PKCS#12 em memória.
    Retorna metadados do certificado.
    Não grava arquivo e não altera o banco.
    """
    if conteudo is None:
        raise CertificadoInvalidoError("Arquivo do certificado não informado.")

    if not isinstance(
        conteudo,
        (
            bytes,
            bytearray,
        ),
    ):
        raise CertificadoInvalidoError("Conteúdo do certificado inválido.")

    conteudo = bytes(conteudo)

    if not conteudo:
        raise CertificadoInvalidoError("O arquivo do certificado está vazio.")

    if len(conteudo) > TAMANHO_MAXIMO_CERTIFICADO:
        raise CertificadoInvalidoError(
            "O arquivo do certificado ultrapassa " "o limite permitido de 10 MB."
        )

    if senha is None:
        raise CertificadoSenhaInvalidaError("Senha do certificado não informada.")

    senha_bytes = str(senha).encode("utf-8")
    if senha_bytes == b"":
        senha_pkcs12 = None
    else:
        senha_pkcs12 = senha_bytes

    try:
        (
            chave_privada,
            certificado,
            certificados_adicionais,
        ) = pkcs12.load_key_and_certificates(
            conteudo,
            senha_pkcs12,
        )

    except ValueError as exc:
        raise CertificadoSenhaInvalidaError(
            "Não foi possível abrir o certificado. "
            "A senha pode estar incorreta ou o "
            "arquivo pode estar corrompido."
        ) from exc

    except Exception as exc:
        raise CertificadoInvalidoError(
            "Não foi possível interpretar o " "arquivo PKCS#12."
        ) from exc

    if certificado is None:
        raise CertificadoInvalidoError(
            "Nenhum certificado foi encontrado " "no arquivo PFX/P12."
        )

    if chave_privada is None:
        raise CertificadoInvalidoError("O arquivo não possui chave privada.")

    valido_de, valido_ate = _validade_certificado(certificado)

    agora = agora_utc()

    if valido_ate <= agora:
        raise CertificadoVencidoError(
            "O certificado está vencido desde " f"{valido_ate.strftime('%d/%m/%Y')}."
        )

    if valido_de > agora:
        raise CertificadoNaoVigenteError(
            "O certificado ainda não está válido. "
            "Início da validade: "
            f"{valido_de.strftime('%d/%m/%Y')}."
        )

    fingerprint = certificado.fingerprint(hashes.SHA256()).hex().lower()

    titular = _obter_common_name(certificado.subject)

    emissor = _obter_common_name(certificado.issuer)

    cnpj = extrair_cnpj_certificado(certificado)

    return {
        "certificado": certificado,
        "chave_privada": chave_privada,
        "certificados_adicionais": (certificados_adicionais or []),
        "titular": titular,
        "emissor": emissor,
        "cnpj": cnpj,
        "serial_number": str(certificado.serial_number),
        "fingerprint_sha256": fingerprint,
        "valido_de": valido_de,
        "valido_ate": valido_ate,
    }


def validar_nome_arquivo(nome_arquivo):
    """
    Valida extensão e normaliza o nome recebido
    pelo upload.
    """
    if not nome_arquivo:
        raise CertificadoInvalidoError("Nome do arquivo não informado.")

    nome_seguro = secure_filename(nome_arquivo)

    if not nome_seguro:
        raise CertificadoInvalidoError("Nome do arquivo inválido.")

    extensao = Path(nome_seguro).suffix.lower()

    if extensao not in EXTENSOES_PERMITIDAS:
        raise CertificadoInvalidoError(
            "Formato inválido. " "Envie um arquivo .pfx ou .p12."
        )

    return nome_seguro


def _gerar_caminho_relativo(tipo, fingerprint):
    """
    Cria caminho interno versionado.

    Exemplo:

        mtls/2026/20260923_141500_ab12cd34.pfx
    """
    agora = agora_utc()
    pasta_tipo = tipo.strip().lower()

    nome = (
        agora.strftime("%Y%m%d_%H%M%S")
        + "_"
        + fingerprint[:12]
        + "_"
        + uuid.uuid4().hex[:8]
        + ".pfx"
    )

    return Path(pasta_tipo) / str(agora.year) / nome


def resolver_caminho_certificado(arquivo_relativo):
    """
    Resolve um caminho armazenado no banco
    sem permitir escapar da pasta configurada.
    """
    if not arquivo_relativo:
        raise CertificadoArquivoNaoEncontradoError(
            "O certificado não possui caminho " "de arquivo cadastrado."
        )

    raiz = obter_diretorio_certificados().resolve()

    destino = (raiz / arquivo_relativo).resolve()

    try:
        destino.relative_to(raiz)

    except ValueError as exc:
        raise CertificadoArquivoNaoEncontradoError(
            "Caminho de certificado inválido."
        ) from exc

    return destino


def _salvar_arquivo_atomicamente(destino, conteudo):
    """
    Grava primeiro em arquivo temporário e,
    somente ao final, faz a substituição atômica.
    """
    destino.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    _proteger_diretorio(destino.parent)

    temporario = destino.with_name(destino.name + ".tmp-" + uuid.uuid4().hex)

    try:
        with open(temporario, "wb") as arquivo:

            arquivo.write(conteudo)

            arquivo.flush()

            os.fsync(arquivo.fileno())

        _proteger_arquivo(temporario)

        os.replace(
            temporario,
            destino,
        )

        _proteger_arquivo(destino)

    finally:
        if temporario.exists():

            try:
                temporario.unlink()

            except OSError:
                pass


def cadastrar_certificado(
    tipo,
    nome_original,
    conteudo,
    senha,
    uploaded_by=None,
):
    """
    Valida, salva e cadastra um novo certificado.

    IMPORTANTE:
    esta função NÃO executa session.commit().

    O admin_routes.py fará:

        certificado = cadastrar_certificado(...)
        registrar_auditoria(...)
        session.commit()

    Isso permite que cadastro + auditoria
    pertençam à mesma transação.

    Retorna:
        Certificado
    """
    tipo = validar_tipo_certificado(tipo)

    nome_original = validar_nome_arquivo(nome_original)

    metadata = validar_certificado_pfx(
        conteudo,
        senha,
    )

    fingerprint = metadata["fingerprint_sha256"]
    existente = (
        session.query(Certificado)
        .filter(
            Certificado.tipo == tipo,
            Certificado.ativo.is_(True),
            Certificado.fingerprint_sha256 == fingerprint,
        )
        .first()
    )

    if existente is not None:
        raise CertificadoDuplicadoError(
            "Este certificado já está ativo " f"como {tipo}."
        )

    senha_criptografada = criptografar_senha(senha)

    arquivo_relativo = _gerar_caminho_relativo(
        tipo,
        fingerprint,
    )

    caminho_absoluto = resolver_caminho_certificado(arquivo_relativo)

    _salvar_arquivo_atomicamente(
        caminho_absoluto,
        conteudo,
    )

    agora = agora_utc()

    try:
        anteriores = (
            session.query(Certificado)
            .filter(
                Certificado.tipo == tipo,
                Certificado.ativo.is_(True),
            )
            .all()
        )

        for anterior in anteriores:

            anterior.ativo = False
            anterior.desativado_em = agora

        novo = Certificado(
            tipo=tipo,
            nome_original=nome_original,
            arquivo_relativo=(arquivo_relativo.as_posix()),
            senha_criptografada=(senha_criptografada),
            titular=metadata["titular"],
            emissor=metadata["emissor"],
            cnpj=metadata["cnpj"],
            serial_number=metadata["serial_number"],
            fingerprint_sha256=(fingerprint),
            valido_de=metadata["valido_de"],
            valido_ate=metadata["valido_ate"],
            ativo=True,
            uploaded_by=uploaded_by,
        )

        session.add(novo)
        session.flush()
        return novo

    except Exception:
        session.rollback()
        try:
            if caminho_absoluto.exists():
                caminho_absoluto.unlink()

        except OSError:
            pass
        raise


def remover_arquivo_certificado(certificado):
    """
    Remove fisicamente o arquivo associado.

    Será utilizado pelo admin_routes caso alguma
    etapa posterior ao cadastro falhe antes do
    commit definitivo.

    NÃO remove o registro do banco.
    """
    if certificado is None:
        return

    try:
        caminho = resolver_caminho_certificado(certificado.arquivo_relativo)

    except CertificateServiceError:
        return

    if not caminho.exists():
        return

    try:
        caminho.unlink()

    except OSError:
        pass


def obter_certificado_ativo(tipo, obrigatorio=True):
    """
    Busca o certificado ativo de um determinado tipo.
    """
    tipo = validar_tipo_certificado(tipo)
    certificado = (
        session.query(Certificado)
        .filter(
            Certificado.tipo == tipo,
            Certificado.ativo.is_(True),
        )
        .order_by(Certificado.criado_em.desc())
        .first()
    )

    if certificado is None and obrigatorio:
        raise CertificadoNaoEncontradoError(
            "Nenhum certificado ativo " f"do tipo {tipo} foi encontrado."
        )

    return certificado


def obter_credenciais_certificado(tipo):
    """
    Retorna as informações necessárias para
    utilizar o certificado internamente.

    Retorno:

        (
            caminho_absoluto,
            senha,
            certificado
        )

    Exemplo futuro no serpro_auth.py:

        caminho, senha, cert = (
            obter_credenciais_certificado(
                CERTIFICADO_MTLS
            )
        )

    A senha NUNCA deve ser retornada pelo frontend.
    """
    certificado = obter_certificado_ativo(tipo)

    caminho = resolver_caminho_certificado(certificado.arquivo_relativo)

    if not caminho.exists():
        raise CertificadoArquivoNaoEncontradoError(
            "O arquivo físico do certificado " "não foi encontrado."
        )

    agora = agora_utc()

    valido_de = _normalizar_datetime_utc(certificado.valido_de)

    valido_ate = _normalizar_datetime_utc(certificado.valido_ate)

    if valido_de > agora:
        raise CertificadoNaoVigenteError(
            "O certificado ativo ainda " "não está vigente."
        )

    if valido_ate <= agora:
        raise CertificadoVencidoError("O certificado ativo está vencido.")

    senha = descriptografar_senha(certificado.senha_criptografada)

    return (
        caminho,
        senha,
        certificado,
    )


def obter_status_certificado(certificado):
    """
    Retorna uma estrutura pronta para uso
    futuro no dashboard administrativo.

    Faixas:

        > 60 dias  -> VALIDO
        <= 60      -> AVISO
        <= 30      -> ATENCAO
        <= 7       -> CRITICO
        vencido    -> VENCIDO
    """
    if certificado is None:

        return {
            "status": ("NAO_CONFIGURADO"),
            "dias_restantes": None,
            "mensagem": ("Nenhum certificado " "configurado."),
        }

    if not certificado.ativo:

        return {
            "status": "INATIVO",
            "dias_restantes": None,
            "mensagem": ("Certificado inativo."),
        }

    agora = agora_utc()

    valido_de = _normalizar_datetime_utc(certificado.valido_de)

    valido_ate = _normalizar_datetime_utc(certificado.valido_ate)

    if valido_de > agora:

        return {
            "status": "NAO_VIGENTE",
            "dias_restantes": None,
            "mensagem": ("O certificado ainda " "não está vigente."),
        }

    diferenca = valido_ate - agora

    dias = diferenca.days

    if valido_ate <= agora:

        status = "VENCIDO"

        mensagem = "Certificado vencido."

    elif dias <= 7:

        status = "CRITICO"

        mensagem = "Certificado próximo do " "vencimento."

    elif dias <= 30:

        status = "ATENCAO"

        mensagem = "Certificado próximo do " "vencimento."

    elif dias <= 60:

        status = "AVISO"

        mensagem = "Certificado deve ser " "renovado em breve."

    else:

        status = "VALIDO"

        mensagem = "Certificado válido."

    return {
        "status": status,
        "dias_restantes": (
            max(
                dias,
                0,
            )
        ),
        "mensagem": mensagem,
        "valido_de": (valido_de.isoformat()),
        "valido_ate": (valido_ate.isoformat()),
    }


def serializar_certificado(certificado):
    """
    Retorna somente informações seguras para
    enviar ao frontend.

    NÃO retorna:
        senha_criptografada
        senha original
        caminho absoluto
    """
    if certificado is None:
        return None

    status = obter_status_certificado(certificado)

    return {
        "id": certificado.id,
        "tipo": certificado.tipo,
        "nome_original": (certificado.nome_original),
        "titular": certificado.titular,
        "emissor": certificado.emissor,
        "cnpj": certificado.cnpj,
        "serial_number": (certificado.serial_number),
        "fingerprint_sha256": (certificado.fingerprint_sha256),
        "valido_de": (
            certificado.valido_de.isoformat() if certificado.valido_de else None
        ),
        "valido_ate": (
            certificado.valido_ate.isoformat() if certificado.valido_ate else None
        ),
        "ativo": certificado.ativo,
        "uploaded_by": (certificado.uploaded_by),
        "criado_em": (
            certificado.criado_em.isoformat() if certificado.criado_em else None
        ),
        "status": status,
    }


def listar_certificados(tipo=None, somente_ativos=False):
    """
    Lista certificados cadastrados.

    Retorna objetos Certificado.
    """
    query = session.query(Certificado)
    if tipo is not None:
        tipo = validar_tipo_certificado(tipo)
        query = query.filter(Certificado.tipo == tipo)

    if somente_ativos:
        query = query.filter(Certificado.ativo.is_(True))

    return query.order_by(Certificado.criado_em.desc()).all()


def obter_certificado_mtls():
    """
    Certificado usado pelo serpro_auth.py.
    """
    return obter_credenciais_certificado(CERTIFICADO_MTLS)


def obter_certificado_autor():
    """
    Certificado usado pelo termo_procurador.py.
    """
    return obter_credenciais_certificado(CERTIFICADO_AUTOR)
