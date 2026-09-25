import base64
import logging
import time

from decouple import config
from dotenv import load_dotenv
from requests_pkcs12 import post

from auth.certificate_service import obter_certificado_mtls

load_dotenv()

logging.basicConfig(level=logging.INFO)

token_cache = {"access_token": None, "expires_in": None, "timestamp": None}


def obter_token_autenticacao():
    """
    Obtém o token de autenticação do SERPRO.
    """
    if (
        token_cache["access_token"]
        and token_cache["expires_in"]
        and token_cache["timestamp"]
    ):
        tempo_passado = time.time() - token_cache["timestamp"]
        if tempo_passado < (token_cache["expires_in"] - 30):
            logging.info("Utilizando token em cache")
            return token_cache["access_token"], token_cache["jwt_token"]

    url = "https://autenticacao.sapi.serpro.gov.br/authenticate"
    caminho_certificado, senha_certificado, certificado_db = obter_certificado_mtls()
    certificado = str(caminho_certificado)
    consumer_key = config("CONSUMER_KEY")
    consumer_secret = config("CONSUMER_SECRET")

    headers = {
        "Authorization": "Basic "
        + base64.b64encode(f"{consumer_key}:{consumer_secret}".encode("utf8")).decode(
            "utf8"
        ),
        "Role-Type": "TERCEIROS",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    body = {"grant_type": "client_credentials"}

    try:
        response = post(
            url,
            data=body,
            headers=headers,
            verify=True,
            pkcs12_filename=certificado,
            pkcs12_password=senha_certificado,
        )
        response.raise_for_status()

        response_data = response.json()
        token_cache["access_token"] = response_data.get("access_token")
        token_cache["jwt_token"] = response_data.get("jwt_token")
        token_cache["expires_in"] = response_data.get("expires_in")
        token_cache["timestamp"] = time.time()

        logging.info("Token obtido com sucesso")

        return token_cache["access_token"], token_cache["jwt_token"]

    except Exception as e:
        logging.error(f"Erro ao obter token de autenticação: {e}")
        raise Exception(f"Erro ao autenticar: {e}")
