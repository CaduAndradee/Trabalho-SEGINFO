from auth_google_client import autenticar_google

auth = autenticar_google()

print("\n========== CREDENCIAIS ==========\n")

print("ID Token:")
print(auth["id_token"])
