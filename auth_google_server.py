from google.oauth2 import id_token
from google.auth.transport import requests

CLIENT_ID = "900364097635-9da62qb43tfl8kfnkh44ve2bn0c81p14.apps.googleusercontent.com"


def verificar_token(token):
    """
    Valida um ID Token emitido pelo Google.

    Retorna:
        dict com os dados do usuário

    Lança exceção caso seja inválido.
    """

    info = id_token.verify_oauth2_token(
        token,
        requests.Request(),
        CLIENT_ID
    )

    return {

        "email": info["email"],

        "nome": info.get("name"),

        "sub": info["sub"],

        "email_verificado": info["email_verified"]

    }