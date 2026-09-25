import base64
import datetime
import hashlib
import io
import os
import uuid
import zipfile
from pathlib import Path

import pandas as pd
from flask import Blueprint, jsonify, request, send_file
from flask_login import current_user
from sqlalchemy import or_

from auth.auth_utils import password_change_required
from database.banco_dominio import get_empresa_codigo
from database.models import Requisicao, agora_utc, session
from utils_serpro.utils import enviar_parcelamento

requisicoes_bp = Blueprint("requisicoes", __name__)
BASE_DIR = Path(__file__).resolve().parent.parent


def obter_pasta_pdf():
    """
    Pasta onde os novos PDFs serão armazenados.

    .env opcional:

        PDF_STORAGE_DIR=pdfs_runtime
    """
    valor = os.getenv("PDF_STORAGE_DIR", "pdfs_runtime").strip()
    caminho = Path(valor).expanduser()

    if not caminho.is_absolute():
        caminho = BASE_DIR / caminho
    caminho = caminho.resolve()
    caminho.mkdir(parents=True, exist_ok=True)
    return caminho


def resolver_pdf(arquivo_relativo):
    """
    Resolve caminho de maneira segura,
    impedindo saída da pasta de PDFs.
    """
    raiz = obter_pasta_pdf().resolve()
    destino = (raiz / arquivo_relativo).resolve()
    try:
        destino.relative_to(raiz)

    except ValueError as exc:
        raise ValueError("Caminho de PDF inválido.") from exc
    return destino


def decodificar_pdf_base64(resposta_base64):
    """
    Converte retorno do SERPRO em bytes.
    """
    if not resposta_base64:
        raise ValueError("PDF Base64 vazio.")
    try:
        pdf_bytes = base64.b64decode(resposta_base64)

    except Exception as exc:
        raise ValueError("Resposta PDF Base64 inválida.") from exc

    if not pdf_bytes:
        raise ValueError("PDF retornado está vazio.")

    if not pdf_bytes.startswith(b"%PDF"):
        raise ValueError("O conteúdo retornado não parece ser um arquivo PDF.")
    return pdf_bytes


def salvar_pdf_novo(resposta_base64):
    """
    Salva novo PDF fora do PostgreSQL.

    Retorna:

        arquivo_relativo
        sha256
        tamanho
    """
    pdf_bytes = decodificar_pdf_base64(resposta_base64)
    agora = agora_utc()
    pasta_relativa = Path(str(agora.year), f"{agora.month:02d}")
    nome = uuid.uuid4().hex + ".pdf"
    arquivo_relativo = pasta_relativa / nome
    destino = resolver_pdf(arquivo_relativo)
    destino.parent.mkdir(parents=True, exist_ok=True)
    temporario = destino.with_name(destino.name + ".tmp")

    try:
        with open(temporario, "wb") as arquivo:
            arquivo.write(pdf_bytes)
            arquivo.flush()
            os.fsync(arquivo.fileno())
        os.replace(temporario, destino)

    finally:
        if temporario.exists():
            try:
                temporario.unlink()
            except OSError:
                pass

    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    return arquivo_relativo.as_posix(), sha256, len(pdf_bytes)


def remover_pdf(arquivo_relativo):
    """
    Remove arquivo quando a transação do banco
    falhar depois da gravação física.
    """
    if not arquivo_relativo:
        return

    try:
        caminho = resolver_pdf(arquivo_relativo)
        if caminho.exists():
            caminho.unlink()
    except Exception:
        pass


def obter_pdf_bytes(requisicao):
    """
    Nova arquitetura:
        arquivo_pdf

    Histórico antigo:
        resposta_base64

    Assim os registros migrados continuam
    funcionando normalmente.
    """
    if requisicao.arquivo_pdf:
        caminho = resolver_pdf(requisicao.arquivo_pdf)
        if not caminho.exists():
            raise FileNotFoundError("Arquivo PDF não encontrado.")
        return caminho.read_bytes()

    if requisicao.resposta_base64:
        return decodificar_pdf_base64(requisicao.resposta_base64)
    raise FileNotFoundError("Esta requisição não possui PDF.")


# ============================================================
# HELPERS
# ============================================================
def obter_dados_requisicao():
    """
    Permite JSON ou formulário.
    """
    if request.is_json:
        dados = request.get_json(silent=True) or {}
        return dados
    return request.form


def validar_mesano(mesano):
    """
    Espera MMYYYY.
    """
    if not mesano:
        return None

    valor = str(mesano).replace("/", "").replace("-", "").strip()
    if len(valor) != 6 or not valor.isdigit():
        raise ValueError("Formato de mês inválido. Use MMYYYY.")

    mes = int(valor[:2])
    ano = int(valor[2:])
    if mes < 1 or mes > 12:
        raise ValueError("Mês inválido.")

    inicio = datetime.datetime(ano, mes, 1, tzinfo=datetime.timezone.utc)
    if mes == 12:
        fim = datetime.datetime(ano + 1, 1, 1, tzinfo=datetime.timezone.utc)
    else:
        fim = datetime.datetime(ano, mes + 1, 1, tzinfo=datetime.timezone.utc)
    return valor, inicio, fim


def nome_pdf_download(requisicao):
    """
    Mantém o padrão atual:

        CODIGO-PARC SN-MMYYYY.pdf
    """
    codigo_empresa = get_empresa_codigo(requisicao.contribuinte) or "0000"
    mesano = requisicao.data_enviostrftime("%m%Y")

    return f"{codigo_empresa}" f"-PARC SN-" f"{mesano}.pdf"


def criar_nome_unico_zip(nome, nomes_existentes):
    """
    Não descarta documentos quando duas
    requisições gerarem o mesmo nome.
    """
    if nome not in nomes_existentes:
        nomes_existentes.add(nome)
        return nome

    caminho = Path(nome)
    contador = 2

    while True:
        candidato = f"{caminho.stem}" f"-{contador}" f"{caminho.suffix}"

        if candidato not in nomes_existentes:
            nomes_existentes.add(candidato)
            return candidato
        contador += 1


# ============================================================
# GERAR DAS
# ============================================================
@requisicoes_bp.route("/gerar_das", methods=["POST"])
@requisicoes_bp.route("/api/requisicoes/gerar", methods=["POST"])
@password_change_required
def gerar_das():
    dados = obter_dados_requisicao()
    numero_contribuinte = str(dados.get("contribuinte", "")).strip()
    id_sistema = str(dados.get("id_sistema", "")).strip()
    id_servico = str(dados.get("id_servico", "")).strip()
    parcela_para_emitir = str(dados.get("parcela_para_emitir", "")).strip()

    try:
        tipo_contribuinte = int(dados.get("tipo_contribuinte", 2))
    except (TypeError, ValueError):
        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Tipo de contribuinte " "inválido."),
                }
            ),
            400,
        )

    if not numero_contribuinte:
        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Contribuinte não informado."),
                }
            ),
            400,
        )

    if not id_sistema or not id_servico:
        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Sistema e serviço " "são obrigatórios."),
                }
            ),
            400,
        )

    if not parcela_para_emitir:
        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Parcela não informada."),
                }
            ),
            400,
        )

    # --------------------------------------------------------
    # SERPRO
    # --------------------------------------------------------
    try:
        (
            resposta_pdf_b64,
            mensagem_erro,
        ) = enviar_parcelamento(
            numero_contribuinte,
            tipo_contribuinte,
            id_sistema,
            id_servico,
            parcela_para_emitir,
        )

    except Exception as exc:

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Erro ao processar " "o pedido."),
                    "details": str(exc),
                }
            ),
            500,
        )

    if not resposta_pdf_b64:

        return (
            jsonify(
                {
                    "success": False,
                    "message": (mensagem_erro or "Erro ao gerar " "o documento DAS."),
                }
            ),
            502,
        )

    # --------------------------------------------------------
    # PDF
    # --------------------------------------------------------

    arquivo_pdf = None

    try:

        (
            arquivo_pdf,
            pdf_sha256,
            pdf_tamanho,
        ) = salvar_pdf_novo(resposta_pdf_b64)

        nova_requisicao = Requisicao(
            usuario_id=(current_user.id),
            contribuinte=(numero_contribuinte),
            tipo_contribuinte=(tipo_contribuinte),
            id_sistema=id_sistema,
            id_servico=id_servico,
            # Novo documento:
            # não grava Base64 no PostgreSQL.
            resposta_base64=None,
            arquivo_pdf=arquivo_pdf,
            pdf_sha256=pdf_sha256,
            pdf_tamanho_bytes=(pdf_tamanho),
            data_envio=agora_utc(),
            data_resposta=agora_utc(),
            status="Concluído",
            response_message=(mensagem_erro or "Sucesso"),
        )

        session.add(nova_requisicao)

        session.commit()

    except Exception:

        session.rollback()

        remover_pdf(arquivo_pdf)

        raise

    return (
        jsonify(
            {
                "success": True,
                "message": ("Documento DAS gerado " "com sucesso."),
                "data": {"id_requisicao": (nova_requisicao.id)},
            }
        ),
        200,
    )


# ============================================================
# ENVIO EM LOTE
# ============================================================
@requisicoes_bp.route("/enviar_em_lote", methods=["POST"])
@requisicoes_bp.route("/api/requisicoes/lote", methods=["POST"])
@password_change_required
def enviar_em_lote():

    if "fileUpload" not in request.files:

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Nenhum arquivo enviado."),
                }
            ),
            400,
        )

    arquivo_excel = request.files["fileUpload"]

    if not arquivo_excel.filename:

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Nenhum arquivo selecionado."),
                }
            ),
            400,
        )

    try:

        df = pd.read_excel(arquivo_excel)

    except Exception as exc:

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Erro ao ler " "a planilha."),
                    "details": str(exc),
                }
            ),
            400,
        )

    required_columns = {
        "CNPJ",
        "ID_SISTEMA",
        "ID_SERVICO",
        "DATA_ENVIO",
    }

    if not required_columns.issubset(df.columns):

        faltantes = sorted(required_columns - set(df.columns))

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Arquivo inválido."),
                    "details": {"colunas_faltantes": (faltantes)},
                }
            ),
            400,
        )

    resultados = []

    for indice, row in df.iterrows():

        numero_contribuinte = str(row["CNPJ"]).strip()

        id_sistema = str(row["ID_SISTEMA"]).strip()

        id_servico = str(row["ID_SERVICO"]).strip()

        data_envio = row["DATA_ENVIO"]

        arquivo_pdf = None

        try:

            # -----------------------------------------------
            # PARCELA
            # -----------------------------------------------

            if isinstance(
                data_envio,
                str,
            ):

                parcela_para_emitir = (
                    data_envio.replace("/", "").replace("-", "").strip()
                )

            elif isinstance(
                data_envio,
                (
                    datetime.datetime,
                    pd.Timestamp,
                ),
            ):

                parcela_para_emitir = data_envio.strftime("%Y%m")

            else:

                raise ValueError("Formato de DATA_ENVIO " "inválido.")

            tipo_contribuinte = 2

            # -----------------------------------------------
            # SERPRO
            # -----------------------------------------------

            (
                resposta_pdf_b64,
                mensagem_erro,
            ) = enviar_parcelamento(
                numero_contribuinte,
                tipo_contribuinte,
                id_sistema,
                id_servico,
                parcela_para_emitir,
            )

            if not resposta_pdf_b64:

                resultados.append(
                    {
                        "linha": (int(indice) + 2),
                        "CNPJ": (numero_contribuinte),
                        "status": "Erro",
                        "mensagem": (
                            mensagem_erro or "Erro ao gerar " "documento DAS."
                        ),
                    }
                )

                continue

            # -----------------------------------------------
            # SALVA PDF
            # -----------------------------------------------

            (
                arquivo_pdf,
                pdf_sha256,
                pdf_tamanho,
            ) = salvar_pdf_novo(resposta_pdf_b64)

            nova_requisicao = Requisicao(
                usuario_id=(current_user.id),
                contribuinte=(numero_contribuinte),
                tipo_contribuinte=2,
                id_sistema=id_sistema,
                id_servico=id_servico,
                resposta_base64=None,
                arquivo_pdf=(arquivo_pdf),
                pdf_sha256=(pdf_sha256),
                pdf_tamanho_bytes=(pdf_tamanho),
                data_envio=(agora_utc()),
                data_resposta=(agora_utc()),
                status="Concluído",
                response_message=(mensagem_erro or "Sucesso"),
            )

            session.add(nova_requisicao)

            session.commit()

            resultados.append(
                {
                    "linha": (int(indice) + 2),
                    "CNPJ": (numero_contribuinte),
                    "status": "Sucesso",
                    "mensagem": ("Documento DAS " "gerado com sucesso."),
                    "id_requisicao": (nova_requisicao.id),
                }
            )

        except Exception as exc:

            session.rollback()

            remover_pdf(arquivo_pdf)

            resultados.append(
                {
                    "linha": (int(indice) + 2),
                    "CNPJ": (numero_contribuinte),
                    "status": "Erro",
                    "mensagem": str(exc),
                }
            )

    return (
        jsonify(
            {
                "success": True,
                "message": ("Processamento em lote " "concluído."),
                "resultados": resultados,
            }
        ),
        200,
    )


@requisicoes_bp.route("/modelo_planilha_lote", methods=["GET"])
@password_change_required
def baixar_modelo_planilha_lote():
    colunas = [
        "CNPJ",
        "ID_SISTEMA",
        "ID_SERVICO",
        "DATA_ENVIO",
    ]

    modelo = pd.DataFrame(columns=colunas)

    instrucoes = pd.DataFrame(
        [
            {
                "Campo": "CNPJ",
                "Descrição": "CNPJ do contribuinte, preferencialmente somente números.",
                "Exemplo": "12345678000190",
            },
            {
                "Campo": "ID_SISTEMA",
                "Descrição": "Modalidade do parcelamento.",
                "Exemplo": "PARCSN",
            },
            {
                "Campo": "ID_SERVICO",
                "Descrição": "Serviço correspondente à modalidade.",
                "Exemplo": "GERARDAS161",
            },
            {
                "Campo": "DATA_ENVIO",
                "Descrição": "Competência da parcela. Informe como uma data válida do Excel.",
                "Exemplo": "01/09/2026",
            },
        ]
    )

    referencias = pd.DataFrame(
        [
            ["PARCSN", "GERARDAS161", "Parcelamento Simples Nacional"],
            ["PARCSN-ESP", "GERARDAS171", "Parcelamento Simples Nacional Especial"],
            ["PERTSN", "GERARDAS181", "PERT Simples Nacional"],
            ["RELPSN", "GERARDAS191", "RELP Simples Nacional"],
            ["PARCMEI", "GERARDAS201", "Parcelamento MEI"],
            ["PARCMEI-ESP", "GERARDAS211", "Parcelamento MEI Especial"],
            ["PERTMEI", "GERARDAS221", "PERT MEI"],
            ["RELPMEI", "GERARDAS231", "RELP MEI"],
        ],
        columns=[
            "ID_SISTEMA",
            "ID_SERVICO",
            "MODALIDADE",
        ],
    )

    arquivo = io.BytesIO()

    with pd.ExcelWriter(
        arquivo,
        engine="openpyxl",
    ) as writer:
        modelo.to_excel(
            writer,
            index=False,
            sheet_name="IMPORTACAO",
        )

        instrucoes.to_excel(
            writer,
            index=False,
            sheet_name="INSTRUCOES",
        )

        referencias.to_excel(
            writer,
            index=False,
            sheet_name="REFERENCIAS",
        )

        planilha_importacao = writer.sheets["IMPORTACAO"]
        planilha_importacao.freeze_panes = "A2"

        planilha_instrucoes = writer.sheets["INSTRUCOES"]
        planilha_instrucoes.column_dimensions["A"].width = 18
        planilha_instrucoes.column_dimensions["B"].width = 70
        planilha_instrucoes.column_dimensions["C"].width = 22

        planilha_referencias = writer.sheets["REFERENCIAS"]
        planilha_referencias.column_dimensions["A"].width = 20
        planilha_referencias.column_dimensions["B"].width = 20
        planilha_referencias.column_dimensions["C"].width = 45

    arquivo.seek(0)

    return send_file(
        arquivo,
        as_attachment=True,
        download_name="modelo_envio_das_lote.xlsx",
        mimetype=(
            "application/vnd.openxmlformats-officedocument." "spreadsheetml.sheet"
        ),
    )


# ============================================================
# CONSULTA JSON
# ============================================================
@requisicoes_bp.route("/consultar_requisicoes", methods=["GET"])
@requisicoes_bp.route("/api/requisicoes", methods=["GET"])
@password_change_required
def consultar_requisicoes():

    contribuinte = (request.args.get("contribuinte") or "").strip()

    mesano = (request.args.get("mesano") or "").strip()

    query = session.query(Requisicao)

    if contribuinte:

        query = query.filter(Requisicao.contribuinte == contribuinte)

    if mesano:

        try:

            (
                _,
                inicio,
                fim,
            ) = validar_mesano(mesano)

        except ValueError as exc:

            return (
                jsonify(
                    {
                        "success": False,
                        "message": str(exc),
                    }
                ),
                400,
            )

        query = query.filter(
            Requisicao.data_envio >= inicio,
            Requisicao.data_envio < fim,
        )

    requisicoes = query.order_by(Requisicao.data_envio.desc()).all()

    resultado = []

    for req in requisicoes:

        resultado.append(
            {
                "id": req.id,
                "contribuinte": (req.contribuinte),
                "data_envio": (req.data_envio.isoformat() if req.data_envio else None),
                "status": req.status,
                "response_message": (req.response_message),
                "tem_pdf": bool(req.arquivo_pdf or req.resposta_base64),
                "usuario_id": (req.usuario_id),
            }
        )

    return jsonify(
        {
            "success": True,
            "data": {
                "requisicoes": (resultado),
                "total": len(resultado),
            },
        }
    )


# ============================================================
# DOWNLOAD INDIVIDUAL
# ============================================================


@requisicoes_bp.route(
    "/baixar_recibo/<int:requisicao_id>",
    methods=["GET"],
)
@requisicoes_bp.route(
    "/api/requisicoes/<int:requisicao_id>/pdf",
    methods=["GET"],
)
@password_change_required
def baixar_recibo(requisicao_id):

    requisicao = session.get(
        Requisicao,
        requisicao_id,
    )

    if requisicao is None:

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Requisição não encontrada."),
                }
            ),
            404,
        )

    try:

        pdf_bytes = obter_pdf_bytes(requisicao)

    except FileNotFoundError as exc:

        return (
            jsonify(
                {
                    "success": False,
                    "message": str(exc),
                }
            ),
            404,
        )

    pdf_file = io.BytesIO(pdf_bytes)

    pdf_file.seek(0)

    return send_file(
        pdf_file,
        mimetype=("application/pdf"),
        as_attachment=True,
        download_name=(nome_pdf_download(requisicao)),
    )


# ============================================================
# DOWNLOAD EM LOTE
# ============================================================


@requisicoes_bp.route(
    "/baixar_todos_recibos",
    methods=["GET"],
)
@requisicoes_bp.route(
    "/api/requisicoes/pdfs",
    methods=["GET"],
)
@password_change_required
def baixar_todos_recibos():

    cnpj = (request.args.get("cnpj_contribuinte") or "").strip()

    mesano = (request.args.get("mesano") or "").strip()

    query = session.query(Requisicao).filter(
        or_(
            Requisicao.arquivo_pdf.isnot(None),
            Requisicao.resposta_base64.isnot(None),
        )
    )

    if cnpj:

        query = query.filter(Requisicao.contribuinte == cnpj)

    if mesano:

        try:

            (
                _,
                inicio,
                fim,
            ) = validar_mesano(mesano)

        except ValueError as exc:

            return (
                jsonify(
                    {
                        "success": False,
                        "message": str(exc),
                    }
                ),
                400,
            )

        query = query.filter(
            Requisicao.data_envio >= inicio,
            Requisicao.data_envio < fim,
        )

    requisicoes = query.order_by(Requisicao.data_envio.asc()).all()

    if not requisicoes:

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Nenhum recibo disponível."),
                }
            ),
            404,
        )

    zip_buffer = io.BytesIO()

    nomes_existentes = set()

    adicionados = 0

    with zipfile.ZipFile(
        zip_buffer,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as zip_file:

        for req in requisicoes:

            try:

                pdf_bytes = obter_pdf_bytes(req)

            except FileNotFoundError:

                # Um arquivo ausente não impede
                # os demais downloads.
                continue

            nome = nome_pdf_download(req)

            nome = criar_nome_unico_zip(
                nome,
                nomes_existentes,
            )

            zip_file.writestr(
                nome,
                pdf_bytes,
            )

            adicionados += 1

    if adicionados == 0:

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Nenhum PDF físico " "foi localizado."),
                }
            ),
            404,
        )

    zip_buffer.seek(0)

    return send_file(
        zip_buffer,
        mimetype=("application/zip"),
        as_attachment=True,
        download_name=("recibos_em_lote.zip"),
    )
