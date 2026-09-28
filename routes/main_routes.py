import datetime
from flask import Blueprint, render_template, request
from auth.auth_utils import admin_required, password_change_required
from database.banco_dominio import get_empresas_por_cnpjs, normalizar_cnpj
from database.models import Requisicao, session

main_bp = Blueprint("main", __name__)

# ============================================================
# INDEX
# ============================================================
@main_bp.route("/", methods=["GET"])
@password_change_required
def index():
    return render_template("index.html")


# ============================================================
# CONSULTA
# ============================================================
@main_bp.route("/consulta", methods=["GET"])
@password_change_required
def consulta():
    """
    Consulta histórico das requisições.

    Comportamento mantido:
    mês padrão = mês anterior.
    """
    contribuinte = (request.args.get("contribuinte") or "").strip()
    mesano_param = (
        request.args.get("mesano", "").replace("/", "").replace("-", "").strip()
    )
    mesano_filtro_db = ""
    mesano_visualizacao = ""

    # --------------------------------------------------------
    # MÊS PADRÃO
    # --------------------------------------------------------
    if not mesano_param:
        hoje = datetime.datetime.now()
        primeiro_dia_mes_atual = hoje.replace(day=1)
        mes_anterior = primeiro_dia_mes_atual - datetime.timedelta(days=1)
        mesano_filtro_db = mes_anterior.strftime("%m%Y")
        mesano_visualizacao = mes_anterior.strftime("%m/%Y")

    else:
        mesano_filtro_db = mesano_param
        if len(mesano_param) == 6:

            mesano_visualizacao = f"{mesano_param[:2]}" f"/" f"{mesano_param[2:]}"
        else:
            mesano_visualizacao = mesano_param

    # --------------------------------------------------------
    # QUERY
    # --------------------------------------------------------
    query = session.query(Requisicao)
    if contribuinte:
        query = query.filter(Requisicao.contribuinte == contribuinte)

    if mesano_filtro_db and len(mesano_filtro_db) == 6:
        try:
            mes = int(mesano_filtro_db[:2])
            ano = int(mesano_filtro_db[2:])
            data_inicio = datetime.datetime(ano, mes, 1, tzinfo=datetime.timezone.utc)
            if mes == 12:
                data_fim = datetime.datetime(
                    ano + 1, 1, 1, tzinfo=datetime.timezone.utc
                )

            else:
                data_fim = datetime.datetime(
                    ano, mes + 1, 1, tzinfo=datetime.timezone.utc
                )

            query = query.filter(
                Requisicao.data_envio >= data_inicio,
                Requisicao.data_envio < data_fim,
            )
        except ValueError:
            pass

    requisicoes = query.order_by(Requisicao.data_envio.desc()).all()

    cnpjs_requisicoes = {
        normalizar_cnpj(req.contribuinte) for req in requisicoes if req.contribuinte
    }

    cnpjs_requisicoes = {cnpj for cnpj in cnpjs_requisicoes if len(cnpj) == 14}

    empresas_dominio = (
        get_empresas_por_cnpjs(cnpjs_requisicoes) if cnpjs_requisicoes else {}
    )

    requisicoes_lista = []

    for req in requisicoes:
        cnpj_normalizado = normalizar_cnpj(req.contribuinte)

        empresa_dominio = empresas_dominio.get(cnpj_normalizado, {})

        requisicoes_lista.append(
            {
                "id": req.id,
                "contribuinte": req.contribuinte,
                "cnpj_normalizado": cnpj_normalizado,
                "codigo_empresa": empresa_dominio.get("codigo"),
                "nome_empresa": (empresa_dominio.get("nome") or ""),
                "data_envio": (
                    req.data_envio.strftime("%d/%m/%Y") if req.data_envio else ""
                ),
                "status": req.status,
                "tem_pdf": bool(req.arquivo_pdf or req.resposta_base64),
            }
        )

    return render_template(
        "consulta.html",
        requisicoes=requisicoes_lista,
        total_guias=len(requisicoes_lista),
        mesano_filtro=mesano_visualizacao,
    )


# ============================================================
# MANUAL DE USO
# ============================================================
@main_bp.route("/manual",  methods=["GET"])
@password_change_required
def manual():
    """
    Exibe o manual de uso da aplicação.
    """
    return render_template("manual.html")

# ============================================================
# ADMINISTRAÇÃO
# ============================================================
@main_bp.route("/admin", methods=["GET"])
@admin_required
@password_change_required
def admin():
    return render_template("admin.html")
