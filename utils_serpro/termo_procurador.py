import base64
import json
from datetime import datetime, timedelta

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from decouple import config
from lxml import etree
from signxml import XMLSigner, methods

from auth.certificate_service import obter_certificado_autor
from utils_serpro.serpro_auth import obter_token_autenticacao


def _assinar_termo(xml: str) -> str:
    caminho, senha, _ = obter_certificado_autor()
    with open(caminho, "rb") as f:
        pfx_data = f.read()

    private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_data, senha.encode())
    root = etree.fromstring(xml.encode())

    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    signed = signer.sign(root, key=private_key, cert=[cert_pem])

    return etree.tostring(signed, encoding="utf-8", xml_declaration=False).decode()


def gerar_token_procurador(cnpj_autor: str, cnpj_contribuinte: str):
    # 1. Autenticação mTLS com o certificado MTLS ativo cadastrado no sistema
    access, jwt = obter_token_autenticacao()

    headers = {
        "Authorization": f"Bearer {access}",
        "jwt_token": jwt,
        "Content-Type": "application/json",
    }

    hoje = datetime.now().strftime("%Y%m%d")
    amanha = (datetime.now() + timedelta(days=5)).strftime("%Y%m%d")
    cnpj_contratante = config("CNPJ_CONT")

    # 2. Montagem do XML assinado pelo certificado AUTOR ativo cadastrado no sistema
    termo = (
        f"<termoDeAutorizacao>"
        f"<dados>"
        f'<sistema id="API Integra Contador" />'
        f'<termo texto="Autorizo a empresa CONTRATANTE, identificada neste termo de autorização como DESTINATÁRIO, a executar as requisições dos serviços web disponibilizados pela API INTEGRA CONTADOR, '
        f"onde terei o papel de AUTOR PEDIDO DE DADOS no corpo da mensagem enviada na requisição do serviço web. Esse termo de autorização está assinado digitalmente com o certificado digital do "
        f'PROCURADOR ou OUTORGADO DO CONTRIBUINTE responsável, identificado como AUTOR DO PEDIDO DE DADOS." />'
        f'<avisoLegal texto="O acesso a estas informações foi autorizado pelo próprio PROCURADOR ou OUTORGADO DO CONTRIBUINTE, '
        f"responsável pela informação, via assinatura digital. É dever do destinatário da autorização e consumidor deste acesso observar a adoção de base legal para o tratamento dos dados "
        f"recebidos conforme artigos 7º ou 11º d-a LGPD (Lei n.º 13.709, de 14 de agosto de 2018), aos direitos do titular dos dados (art. 9º, 17 e 18, da LGPD) e aos princípios que norteiam todos os tratamentos de dados no Brasil "
        f'(art. 6º, da LGPD)."/>'
        f'<finalidade texto="A finalidade única e exclusiva desse TERMO DE AUTORIZAÇÃO, é garantir que o CONTRATANTE apresente a API INTEGRA CONTADOR esse consentimento do PROCURADOR ou OUTORGADO DO CONTRIBUINTE assinado digitalmente, '
        f'para que possa realizar as requisições dos serviços web da API INTEGRA CONTADOR em nome do AUTOR PEDIDO DE DADOS (PROCURADOR ou OUTORGADO DO CONTRIBUINTE)." />'
        f'<dataAssinatura data="{hoje}"/>'
        f'<vigencia data="{amanha}"/>'
        f'<destinatario numero="{cnpj_contratante}" nome="CONTRATANTE" tipo="PJ" papel="contratante"/>'
        f'<assinadoPor numero="{cnpj_autor}" nome="AUTOR" tipo="PJ" papel="autor pedido de dados"/>'
        f"</dados>"
        f"</termoDeAutorizacao>"
    )

    termo_assinado = _assinar_termo(termo)
    xml_b64 = base64.b64encode(termo_assinado.encode("utf-8")).decode("utf-8")

    payload = {
        "contratante": {"numero": cnpj_contratante, "tipo": 2},
        "autorPedidoDados": {"numero": cnpj_autor, "tipo": 2},
        "contribuinte": {"numero": cnpj_contribuinte, "tipo": 2},
        "pedidoDados": {
            "idSistema": "AUTENTICAPROCURADOR",
            "idServico": "ENVIOXMLASSINADO81",
            "versaoSistema": "1.0",
            "dados": json.dumps({"xml": xml_b64}),
        },
    }

    url_apoiar = "https://gateway.apiserpro.serpro.gov.br/integra-contador/v1/Apoiar"
    response = requests.post(url_apoiar, json=payload, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return json.loads(data["dados"]).get("autenticar_procurador_token")
    elif response.status_code == 304:
        return response.headers.get("etag", "").strip('"').partition(":")[
            2
        ] or response.headers.get("etag", "").strip('"')
    else:
        raise Exception(f"Erro Apoiar: {response.text}")
