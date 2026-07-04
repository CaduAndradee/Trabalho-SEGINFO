from auth_google_server import verificar_token

jwt = input("Cole o ID Token:\n")

usuario = verificar_token(jwt)

print()

print(usuario)