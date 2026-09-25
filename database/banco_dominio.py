import logging
import os
import re
from pathlib import Path

import sqlanydb
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)

PASTA_ATUAL = Path(__file__).resolve().parent
ARQUIVO_ENV_ATUAL = PASTA_ATUAL / ".env"
ARQUIVO_ENV_RAIZ = PASTA_ATUAL.parent / ".env"


if ARQUIVO_ENV_ATUAL.exists():
    load_dotenv(dotenv_path=ARQUIVO_ENV_ATUAL)
elif ARQUIVO_ENV_RAIZ.exists():
    load_dotenv(dotenv_path=ARQUIVO_ENV_RAIZ)
else:
    logging.warning("Arquivo .env não encontrado.")


def normalizar_cnpj(valor):
    """
    Remove qualquer caractere que não seja número.
    Exemplos:
        60.797.843/0001-92 -> 60797843000192
    """
    if valor is None:
        return ""
    return re.sub(r"\D", "", str(valor))


def obter_parametros_dominio():
    """
    Obtém as configurações de conexão com o banco Domínio
    através do .env.
    """
    host = os.getenv("DOMINIO_HOST", "").strip()
    port = os.getenv("DOMINIO_PORT", "2638").strip()
    dbname = os.getenv("DOMINIO_DB", "").strip()
    user = os.getenv("DOMINIO_USER", "").strip()
    password = os.getenv("DOMINIO_PASSWORD", "")
    campos = {
        "DOMINIO_HOST": host,
        "DOMINIO_PORT": port,
        "DOMINIO_DB": dbname,
        "DOMINIO_USER": user,
        "DOMINIO_PASSWORD": password,
    }

    ausentes = [nome for nome, valor in campos.items() if not valor]
    if ausentes:
        raise RuntimeError(
            "Configuração do banco Domínio incompleta. Variáveis ausentes no .env: "
            + ", ".join(ausentes)
        )
    return {
        "host": host,
        "port": int(port),
        "dbname": dbname,
        "user": user,
        "password": password,
    }


class DatabaseConnection:
    def __init__(self, host, port, dbname, user, password):
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self.conn_str = {
            "uid": user,
            "pwd": password,
            "host": f"{host}:{port}",
            "dbn": dbname,
        }
        self.conn = None

    def connect(self):
        """
        Abre a conexão com o banco Domínio.
        """
        try:
            logging.info(
                "Conectando ao banco Domínio %s:%s / %s...",
                self.host,
                self.port,
                self.dbname,
            )
            self.conn = sqlanydb.connect(**self.conn_str)
            logging.info("Conexão com o banco Domínio estabelecida.")
            return True

        except sqlanydb.Error as exc:
            logging.error("Erro ao conectar ao banco Domínio: %s", exc)
            self.conn = None
            return False

    def close(self):
        """
        Fecha a conexão.
        """
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            finally:
                self.conn = None

    def execute_query(self, query, params=None):
        """
        Executa SELECT e retorna fetchall().
        """
        if self.conn is None:
            logging.error("Conexão com o banco Domínio não estabelecida.")
            return None

        cursor = self.conn.cursor()

        try:
            if params is not None:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor.fetchall()

        except sqlanydb.Error as exc:
            logging.error("Erro ao consultar banco Domínio: %s", exc)
            return None

        finally:
            try:
                cursor.close()
            except Exception:
                pass


def criar_conexao_dominio():
    """
    Cria e conecta uma instância DatabaseConnection.
    Retorna:
        DatabaseConnection
    ou:
        None
    """
    try:
        parametros = obter_parametros_dominio()
    except Exception as exc:
        logging.error("%s", exc)
        return None

    conexao = DatabaseConnection(**parametros)

    if not conexao.connect():
        return None
    return conexao


# ============================================================
# EXPRESSÃO SQL PARA NORMALIZAR CNPJ
# ============================================================
SQL_CNPJ_NORMALIZADO = """
    REPLACE(
        REPLACE(
            REPLACE(
                REPLACE(
                    TRIM(cgce_emp),
                    '.',
                    ''
                ),
                '/',
                ''
            ),
            '-',
            ''
        ),
        ' ',
        ''
    )
"""


# ============================================================
# CONSULTA EM LOTE
# ============================================================
def get_empresas_por_cnpjs(cnpjs):
    """
    Busca várias empresas de uma única vez no Domínio.
    Retorno:
    {
        "60797843000192": {
            "codigo": 3354,
            "nome": "MARCUS VINICIUS MARINO LTDA.",
            "cnpj": "60797843000192"
        }
    }
    Se o banco Domínio estiver indisponível,
    retorna {} para não quebrar o restante do sistema.
    """
    cnpjs_normalizados = {normalizar_cnpj(cnpj) for cnpj in cnpjs if cnpj}

    cnpjs_normalizados = {cnpj for cnpj in cnpjs_normalizados if len(cnpj) == 14}

    if not cnpjs_normalizados:
        return {}

    conexao = criar_conexao_dominio()

    if conexao is None:
        logging.error(
            "Não foi possível consultar empresas porque o banco Domínio está indisponível."
        )
        return {}

    try:
        lista_cnpjs = sorted(cnpjs_normalizados)
        placeholders = ", ".join("?" for _ in lista_cnpjs)
        query = f"""
            SELECT
                codi_emp,
                nome_emp,
                cgce_emp

            FROM bethadba.geempre

            WHERE
                {SQL_CNPJ_NORMALIZADO}
                IN (
                    {placeholders}
                )
        """

        resultados = conexao.execute_query(
            query,
            tuple(lista_cnpjs),
        )

        if not resultados:
            return {}
        empresas = {}

        for linha in resultados:
            codigo = linha[0]
            nome = linha[1]
            cnpj_banco = linha[2]
            cnpj_normalizado = normalizar_cnpj(cnpj_banco)

            if not cnpj_normalizado:
                continue

            empresas[cnpj_normalizado] = {
                "codigo": codigo,
                "nome": (str(nome).strip() if nome else ""),
                "cnpj": cnpj_normalizado,
            }

        return empresas

    except Exception as exc:
        logging.exception("Erro ao consultar empresas no banco Domínio: %s", exc)
        return {}
    finally:
        conexao.close()


def get_empresa_dados(cnpj):
    """
    Busca código + nome da empresa pelo CNPJ.
    Retorno:
        {
            "codigo": 3354,
            "nome": "...",
            "cnpj": "60797843000192"
        }
    ou None.
    """
    cnpj_limpo = normalizar_cnpj(cnpj)

    if len(cnpj_limpo) != 14:
        logging.warning("CNPJ inválido para consulta no Domínio: %s", cnpj)
        return None

    empresas = get_empresas_por_cnpjs([cnpj_limpo])
    return empresas.get(cnpj_limpo)


def get_empresa_codigo(cnpj):
    """
    Mantém compatibilidade com o código já existente.
    Utilizado para nomear os PDFs:
        CODIGO-PARC SN-MMYYYY.pdf
    """
    logging.info("Buscando código da empresa para o CNPJ: %s", cnpj)
    empresa = get_empresa_dados(cnpj)

    if not empresa:
        logging.warning("Empresa não encontrada no Domínio para o CNPJ: %s", cnpj)
        return None

    codigo = empresa.get("codigo")
    logging.info("Código da empresa encontrado: %s", codigo)
    return codigo


def testar_conexao_dominio():
    """
    Testa somente a conexão com o banco Domínio.
    """
    conexao = criar_conexao_dominio()

    if conexao is None:
        return False
    try:
        resultado = conexao.execute_query("SELECT 1")

        return bool(resultado)

    finally:
        conexao.close()


if __name__ == "__main__":
    print("Testando conexão com o banco Domínio...")
    if testar_conexao_dominio():
        print("Conexão com o banco Domínio: OK")
    else:
        print("Conexão com o banco Domínio: ERRO")
