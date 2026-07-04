import socket
import struct
import uuid
import os
import threading
import ssl
from auth_google_client import autenticar_google
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2 import id_token
from google.auth.transport.requests import Request

def recvall(tls_socket, n):
    data = bytearray()
    while len(data) < n:
        packet = tls_socket.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0] #>I = Big-Endian Unsigned Interger
    return recvall(sock, msglen)

def send_msg(sock, msg):
    msg_bytes = bytes(msg, 'utf-8') if isinstance(msg, str) else msg
    msglen = len(msg_bytes)
    prefixo = struct.pack('>I', msglen)
    sock.sendall(prefixo + msg_bytes)

def encrypt_message(texto_claro, meu_id_bytes, peer_id_bytes, peer_data):

    #1
    seq_no = peer_data["seq_send"]
    peer_data["seq_send"] += 1

    #2
    seq_no_bytes = struct.pack('>Q', seq_no)

    #3
    nonce = peer_data["IV_base_send"] + seq_no_bytes

    #4
    aad = meu_id_bytes + peer_id_bytes + seq_no_bytes

    #5
    aesgcm = AESGCM(peer_data["key_send"])
    ciphertext_and_tag = aesgcm.encrypt(
        nonce,
        texto_claro.encode('utf-8'),
        aad
    )

    #6
    frame_e2e = nonce + meu_id_bytes + peer_id_bytes + seq_no_bytes + ciphertext_and_tag
    
    return frame_e2e

def decrypt_message(frame_e2e, peer_data):
    
    #1
    nonce = frame_e2e[:12]
    sender_id_bytes = frame_e2e[12:28]
    recipient_id_bytes = frame_e2e[28:44]
    seq_no_bytes = frame_e2e[44:52]
    ciphertext_and_tag = frame_e2e[52:]

    #2
    seq_no = struct.unpack('>Q', seq_no_bytes)[0]

    #3
    if seq_no <= peer_data["seq_recv"]:
        print(f"[-] ALERTA: Ataque de replay detectado! Msg {seq_no} descartada.")
        return None

    #4
    aad = sender_id_bytes + recipient_id_bytes + seq_no_bytes

    #5
    aesgcm = AESGCM(peer_data["key_recv"])
    try:
        texto_claro_bytes = aesgcm.decrypt(
            nonce,
            ciphertext_and_tag,
            aad
        )
        
        peer_data["seq_recv"] = seq_no
        return texto_claro_bytes.decode('utf-8')
        
    except Exception as e:
        print("[-] ALERTA: Falha na Tag GCM! Mensagem adulterada no tráfego.")
        return None
    
def input_thread(client_socket, meu_id_bytes, peers):

    print("\n[+] Chat E2E liberado! Digite sua mensagem e aperte Enter para enviar:")
    print("    -> DICA PARA A APRESENTAÇÃO:")
    print("       Digite '/adulterar <msg>' para testar falha na Tag GCM.")
    print("       Digite '/replay <msg>' para testar ataque de repetição.\n")
    
    while True:
        texto = input()
        if not texto:
            continue
            
        if not peers:
            print("[-] Nenhum contato online no momento. Aguarde alguém entrar.")
            continue

        for peer_id_bytes, peer_data in peers.items():
            
            #1
            if texto.startswith("/adulterar "):
                msg_real = texto.replace("/adulterar ", "")
                frame_e2e = encrypt_message(msg_real, meu_id_bytes, peer_id_bytes, peer_data)
                
                frame_hackeado = bytearray(frame_e2e)
                frame_hackeado[-1] = frame_hackeado[-1] ^ 0xFF # Inverte os bits do último byte
                
                print("[!] ATENÇÃO: Enviando pacote corrompido de propósito...")
                send_msg(client_socket, b"MSG_" + bytes(frame_hackeado))

            #2
            elif texto.startswith("/replay "):
                msg_real = texto.replace("/replay ", "")
                
                frame_e2e = encrypt_message(msg_real, meu_id_bytes, peer_id_bytes, peer_data)
                
                print("[!] ATENÇÃO: Enviando a mensagem original...")
                send_msg(client_socket, b"MSG_" + frame_e2e)
                
                #hacker interceptou e manda o mesmo frame de novo
                print("[!] ATENÇÃO: Reenviando a mesma mensagem interceptada (Ataque de Replay)...")
                send_msg(client_socket, b"MSG_" + frame_e2e)

            #3
            else:
                frame_e2e = encrypt_message(texto, meu_id_bytes, peer_id_bytes, peer_data)
                send_msg(client_socket, b"MSG_" + frame_e2e)

def autenticar_usuario():
    auth = autenticar_google()
    return auth["id_token"]

def start_client():
    HOST = 'seginfo2026.duckdns.org'
    PORT = 5000

    # ==========================
    # AUTH GOOGLE (OIDC)
    # ==========================
    id_token = autenticar_usuario()
    print("[CLIENT] Usuário autenticado no Google")

    # ==========================
    # TLS 1.3
    # ==========================
    print("[*] Preparando túnel TLS 1.3...")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_default_certs()
    context.check_hostname = True

    # =================================================================
    # CRIANDO O TÚNEL ÚNICO E CONECTANDO
    # =================================================================
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
        
        # Envelopa o socket cru ANTES de conectar
        with context.wrap_socket(raw_socket, server_hostname=HOST) as tls_socket:
            
            try:
                # Conecta usando o socket já blindado
                tls_socket.connect((HOST, PORT))
                print(f"[+] Conectado a {HOST} via TLS 1.3 validado pela Let's Encrypt!")

                peers = {} 

                # ==========================
                # ENVIO AUTH OIDC
                # ==========================
                send_msg(tls_socket, b"AUTH" + id_token.encode())
                resposta = recv_msg(tls_socket)

                if resposta != b"AUTH_OK":
                    print("[-] Falha na autenticação do Google no servidor.")
                    return

                # IDENTIFICAÇÃO E GERAÇÃO DE CHAVES
                meu_uuid = uuid.uuid4()
                client_id_bytes = meu_uuid.bytes 
                print(f"[*] Meu UUID: {meu_uuid}")

                print("[*] Gerando chaves X25519 efêmeras...")
                sk_client = x25519.X25519PrivateKey.generate()
                
                pk_client = sk_client.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )

                # ==========================
                # REGISTRO E HANDSHAKE
                # ==========================
                # envia o registro inicial: ID (16B) + Chave Pública (32B) = 48 Bytes
                payload_registro = client_id_bytes + pk_client
                print(f"[*] Enviando registro ao servidor...")
                send_msg(tls_socket, payload_registro)

                print("[*] Aguardando handshake autenticado do servidor...")
                resposta = recv_msg(tls_socket)

                if not resposta:
                    print("[-] Servidor encerrou a conexão.")
                    return

                with open("server.crt", "rb") as f:
                    trusted_cert = f.read()

                # [4B tamanho][certificado][assinatura][salt]
                cert_len = struct.unpack(">I", resposta[:4])[0]

                inicio_cert = 4
                fim_cert = inicio_cert + cert_len

                certificado_recebido = resposta[inicio_cert:fim_cert]
                assinatura = resposta[fim_cert:fim_cert + 256]
                salt_srv = resposta[fim_cert + 256:fim_cert + 256 + 16]

                # certificate Pinning (Defesa em profundidade mantida do TP3)
                if certificado_recebido != trusted_cert:
                    print("[-] ALERTA: Certificado do servidor não confere com o pinado!")
                    return

                print("[+] Certificado pinado validado com sucesso!")

                # extrai a chave pública do certificado
                from cryptography import x509

                try:
                    cert = x509.load_pem_x509_certificate(certificado_recebido)
                    pk_server = cert.public_key()
                except Exception as e:
                    print(f"[-] Erro ao carregar certificado: {e}")
                    return

                print("[*] Verificando assinatura RSA-PSS...")

                # reconstrói o material assinado
                pk_server_bytes = pk_server.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                material_assinado = (
                    pk_server_bytes +
                    pk_client +
                    client_id_bytes +
                    salt_srv
                )

                # valida a assinatura
                try:
                    pk_server.verify(
                        assinatura,
                        material_assinado,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print("[+] SUCESSO! O servidor foi autenticado corretamente.")

                except Exception:
                    print("[-] ALERTA DE SEGURANÇA: Assinatura inválida!")
                    return
                
                # ENVIO
                print("\n[+] Pronto! Sistema de mensageria liberado.")
                
                threading.Thread(
                    target=input_thread, 
                    args=(tls_socket, client_id_bytes, peers),
                    daemon=True
                ).start()
                
                # RENDEZVOUS E MENSAGENS (Aqui não muda nada, só identação)
                while True:
                    dados = recv_msg(tls_socket)
                    if not dados:
                        print("[-] Desconectado do servidor.")
                        break
                    
                    if dados.startswith(b"PEER"):
                        peer_id_bytes = dados[4:20]
                        peer_pk_bytes = dados[20:52]
                        peer_id_str = str(uuid.UUID(bytes=peer_id_bytes))
                        
                        print(f"\n[+] Novo contato online: {peer_id_str}")
                        
                        peer_pk_obj = x25519.X25519PublicKey.from_public_bytes(peer_pk_bytes)
                        
                        # calcula o Segredo Compartilhado Z_AB via ECDH
                        Z_AB = sk_client.exchange(peer_pk_obj) 
                        print("[*] Segredo Z calculado. Derivando chaves AES-GCM via HKDF...")
                        
                        if client_id_bytes < peer_id_bytes:
                            info_send = b"A2B"
                            info_recv = b"B2A"
                        else:
                            info_send = b"B2A"
                            info_recv = b"A2B"

                        # deriva a Chave de Envio
                        hkdf_send = HKDF(
                            algorithm=hashes.SHA256(),
                            length=16,
                            salt=salt_srv,
                            info=info_send
                        )
                        key_send = hkdf_send.derive(Z_AB)

                        # deriva a Chave de Recebimento
                        hkdf_recv = HKDF(
                            algorithm=hashes.SHA256(),
                            length=16,
                            salt=salt_srv,
                            info=info_recv
                        )
                        key_recv = hkdf_recv.derive(Z_AB)

                        # inicializa a tabela do peer
                        peers[peer_id_bytes] = {
                            "public_key": peer_pk_bytes,
                            "key_send": key_send,
                            "key_recv": key_recv,
                            "seq_send": 0,
                            "seq_recv": -1,
                            "IV_base_send": os.urandom(4), 
                            "IV_base_recv": os.urandom(4)
                        }
                        print("[+] Chaves de criptografia E2E forjadas e guardadas com sucesso!")
                        print("-> Digite uma mensagem a qualquer momento para testar o envio:")
                        
                    # RECEBIMENTO
                    elif dados.startswith(b"MSG_"):
                        frame_e2e = dados[4:]
                        sender_id_bytes = frame_e2e[12:28]
                        
                        if sender_id_bytes in peers:
                            texto_decifrado = decrypt_message(frame_e2e, peers[sender_id_bytes])
                            if texto_decifrado:
                                remetente_str = str(uuid.UUID(bytes=sender_id_bytes))
                                print(f"\n[Mensagem Segura de {remetente_str[:8]}...]: {texto_decifrado}")
                        else:
                            print("\n[-] Recebeu pacote de um contato não registrado localmente.")

            except ssl.SSLError as e:
                print(f"[-] Erro de segurança TLS ao conectar: {e}")
            except Exception as e:
                print(f"[-] Erro de conexão: {e}")
        
        

if __name__ == "__main__":
    start_client()