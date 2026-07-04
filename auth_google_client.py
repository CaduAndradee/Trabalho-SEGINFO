from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]

CLIENT_SECRET_FILE = "client_secret_900364097635-9da62qb43tfl8kfnkh44ve2bn0c81p14.apps.googleusercontent.com.json"


def autenticar_google():
    print("\n[AUTH] Iniciando login Google...\n")

    flow = InstalledAppFlow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES
    )

    creds = flow.run_local_server(port=0)

    if not creds.id_token:
        raise Exception("Falha ao obter ID Token do Google")

    print("[AUTH] Login OK")

    return {
        "id_token": creds.id_token,
        "email": None  # será validado no servidor
    }