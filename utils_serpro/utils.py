import datetime
import json
import logging
import re

import requests
from decouple import config

from database.models import Requisicao, session
from utils_serpro.serpro_auth import obter_token_autenticacao
from utils_serpro.termo_procurador import gerar_token_procurador

logging.basicConfig(level=logging.INFO)


def fazer_requisicao_serpro(
    endpoint="/Emitir", method="POST", data=None, token_procurador=None
):
    """
    Faz uma requisição ao endpoint da API do SERPRO, injetando o token de procuração se houver.
    """
    try:
        access_token, jwt_token = obter_token_autenticacao()
    except Exception as e:
        logging.error(f"Erro ao obter o token de autenticação mTLS: {e}")
        return None, f"Erro Auth: {str(e)}"

    url = f"https://gateway.apiserpro.serpro.gov.br/integra-contador/v1{endpoint}"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "jwt_token": jwt_token,
    }
    if token_procurador:
        headers["autenticar_procurador_token"] = token_procurador

    logging.info(f"Fazendo requisição para {url}")

    try:
        if method == "POST":
            response = requests.post(url, headers=headers, data=json.dumps(data))
        elif method == "GET":
            response = requests.get(url, headers=headers)
        else:
            return None, "Método HTTP não suportado."

        logging.info(f"Status da resposta: {response.status_code}")

        if response.status_code == 200:
            response_data = response.json()
            mensagens = response_data.get("mensagens", [])
            mensagem_texto = ", ".join(
                [f"{m.get('codigo', '')}: {m.get('texto', '')}" for m in mensagens]
            )

            if response_data.get("dados"):
                dados_internos = json.loads(response_data["dados"])
                if "docArrecadacaoPdfB64" in dados_internos:
                    return (
                        dados_internos["docArrecadacaoPdfB64"],
                        mensagem_texto or None,
                    )

            return None, mensagem_texto or "Nenhum dado encontrado."

        else:
            try:
                err_data = response.json()
                msg = ", ".join(
                    [
                        f"{m.get('codigo', '')}: {m.get('texto', '')}"
                        for m in err_data.get("mensagens", [])
                    ]
                )
                return None, msg
            except:
                return None, f"Erro {response.status_code}: {response.text}"

    except requests.RequestException as e:
        return None, f"Erro de rede: {str(e)}"


def formatar_numero_documento(numero):
    return re.sub(r"\D", "", str(numero))


def montar_json_gerardas(
    numero_contribuinte, tipo_contribuinte, id_sistema, id_servico, parcela_para_emitir
):
    """
    Monta o JSON com a separação correta de Contratante e Autor.
    """
    cnpj_contratante = formatar_numero_documento(config("CNPJ_CONT"))
    cnpj_autor = formatar_numero_documento(config("AUTOR_PEDIDO"))

    return {
        "contratante": {"numero": cnpj_contratante, "tipo": 2},
        "autorPedidoDados": {"numero": cnpj_autor, "tipo": 2},
        "contribuinte": {
            "numero": formatar_numero_documento(numero_contribuinte),
            "tipo": tipo_contribuinte,
        },
        "pedidoDados": {
            "idSistema": id_sistema,
            "idServico": id_servico,
            "versaoSistema": "1.0",
            "dados": json.dumps({"parcelaParaEmitir": parcela_para_emitir}),
        },
    }


def enviar_parcelamento(
    numero_contribuinte, tipo_contribuinte, id_sistema, id_servico, parcela_para_emitir
):
    """
    Fluxo principal da emissão.

    Quando Contratante e Autor do Pedido de Dados são o mesmo CNPJ,
    a requisição é enviada diretamente.

    Quando são CNPJs diferentes, é gerado o token de procurador para
    autorizar o Contratante a realizar a requisição em nome do Autor.
    """
    num_limpo = formatar_numero_documento(numero_contribuinte)
    cnpj_contratante = formatar_numero_documento(config("CNPJ_CONT"))
    cnpj_autor = formatar_numero_documento(config("AUTOR_PEDIDO"))

    token_proc = None

    if cnpj_contratante != cnpj_autor:
        try:
            logging.info(
                "Contratante e Autor do Pedido são diferentes. "
                "Gerando token de procurador."
            )

            token_proc = gerar_token_procurador(
                cnpj_autor=cnpj_autor, cnpj_contribuinte=num_limpo
            )

            if not token_proc:
                return None, "Falha Procuração: token de procurador não foi retornado."

        except Exception as e:
            logging.error(f"Falha na fase de procuração: {e}")
            return None, f"Falha Procuração: {str(e)}"

    else:
        logging.info(
            "Contratante e Autor do Pedido são o mesmo CNPJ. "
            "Token de procurador não é necessário."
        )

    json_data = montar_json_gerardas(
        num_limpo, tipo_contribuinte, id_sistema, id_servico, parcela_para_emitir
    )

    return fazer_requisicao_serpro(data=json_data, token_procurador=token_proc)


def salvar_resposta_recibo(
    requisicao_id, resposta_base64, status="Concluído", mensagem="Sucesso"
):
    requisicao = session.query(Requisicao).get(requisicao_id)
    if requisicao:
        requisicao.resposta_base64 = resposta_base64
        requisicao.status = status
        requisicao.response_message = mensagem
        requisicao.data_resposta = datetime.datetime.now(datetime.timezone.utc)
        session.commit()
        print(f"Requisição {requisicao_id} atualizada.")
    else:
        print(f"Requisição {requisicao_id} não encontrada.")
