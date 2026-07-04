from auth_google_client import autenticar_google

auth = autenticar_google()

print("\n========== CREDENCIAIS ==========\n")

print("Access Token:")
print(auth["access_token"])

print("\n-------------------------------\n")

print("ID Token:")
print(auth["id_token"])