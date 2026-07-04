import socket
import struct
import threading
import uuid
import os
import ssl
from auth_google_server import verificar_token
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

#tabela global de sessões do servidor para registrar os clientes
sessions = {}

#GERANDO A CHAVE RSA DO SERVIDOR (2048 bits)
print("[*] Carregando chave RSA do servidor...")
with open("server.key", "rb") as f:
    sk_server = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("server.crt", "rb") as f:
    server_crt = f.read()

#extraindo a chave pública do servidor em formato de bytes (DER)
pk_server_bytes = sk_server.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

#GERAÇÃO DE SALT
salt_srv_global = os.urandom(16)

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def send_msg(sock, msg):
    msg_bytes = bytes(msg, 'utf-8') if isinstance(msg, str) else msg
    msglen = len(msg_bytes)
    prefixo = struct.pack('>I', msglen)
    sock.sendall(prefixo + msg_bytes)

def handle_client(conn, addr):
    print(f"[*] Nova conexão de {addr}")
    
    try:
        # ==========================
        # AUTH GOOGLE (OBRIGATÓRIO)
        # ==========================

        dados = recv_msg(conn)

        if not dados or not dados.startswith(b"AUTH"):
            print("[-] Cliente sem autenticação")
            conn.close()
            return

        token = dados[4:].decode()

        try:
            user = verificar_token(token)
        except Exception as e:
            print(f"[-] AUTH FALHOU: {e}")
            send_msg(conn, b"AUTH_FAIL")
            conn.close()
            return

        print(f"[+] AUTH OK: {user['email']}")

        send_msg(conn, b"AUTH_OK")
        
        #REGISTRO DO CLIENTE
        dados_registro = recv_msg(conn)
        
        if not dados_registro or len(dados_registro) != 48:   #(16 bytes do ID + 32 bytes da chave X25519)
            print(f"[-] Erro ao receber registro de {addr} (Tamanho incorreto). Desconectando.")
            return

        client_id_bytes = dados_registro[:16] 
        pk_client_bytes = dados_registro[16:] 
        client_id_str = str(uuid.UUID(bytes=client_id_bytes))

        print(f"[+] Cliente registrado: {client_id_str}")
        
        #HANDSHAKE

        salt_srv = salt_srv_global
        
        #H = SHA256(pk_server || pk_client || client_id || salt)
        material_para_assinar = pk_server_bytes + pk_client_bytes + client_id_bytes + salt_srv
        
        #O servidor assina o pacote para provar sua autenticidade
        assinatura = sk_server.sign(
            material_para_assinar,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        #Guarda as informações do cliente na memória do servidor
        sessions[client_id_bytes] = {
            "conn": conn,
            "public_key": pk_client_bytes,
            "salt": salt_srv,
            "seq_recv": -1,
            "seq_send": 0
        }

        cert_len = struct.pack(">I", len(server_crt))

        resposta_autenticada = (
            struct.pack(">I", len(server_crt))
            + server_crt
            + assinatura
            + salt_srv
        )
        
        print(f"[*] Enviando handshake finalizado para {client_id_str[:8]}...")
        send_msg(conn, resposta_autenticada)

        #TROCA DE CHAVES
        #avisa sobre o novato
        for peer_id_bytes, peer_data in sessions.items():
            if peer_id_bytes != client_id_bytes:
                msg_para_novo = b"PEER" + peer_id_bytes + peer_data["public_key"]
                send_msg(conn, msg_para_novo)
                
                msg_para_antigo = b"PEER" + client_id_bytes + pk_client_bytes
                send_msg(peer_data["conn"], msg_para_antigo)

        while True:
            dados = recv_msg(conn)
            if not dados:
                break
            
            #se for um pacote de chat criptografado
            if dados.startswith(b"MSG_"):
                #o servidor nao tenta decifrar. Ele so fatia os bytes publicos
                #o destinatário (16 bytes) começa no byte 32 do pacote
                #calculo: 4B ("MSG_") + 12B (Nonce) + 16B (Remetente) = Posição 32
                recipient_id_bytes = dados[32:48]
                
                if recipient_id_bytes in sessions:
                    #pega a conexão TCP do destinatário e repassa o bloco de bytes inteiro
                    destinatario_conn = sessions[recipient_id_bytes]["conn"]
                    send_msg(destinatario_conn, dados)
                    print(f"[*] Relay: Repassando pacote E2E de {client_id_str[:8]} para o destino.")
                else:
                    print(f"[-] Relay falhou: Destinatário offline.")
            
            else:
                print(f"[*] Mensagem de controle desconhecida recebida de {client_id_str[:8]}")

    except Exception as e:
        print(f"[-] Erro com a conexão de {addr}: {e}")
    finally:
        #quando o cliente fecha o terminal ou a internet cai, removemos da memória
        if 'client_id_bytes' in locals() and client_id_bytes in sessions:
            del sessions[client_id_bytes]
        conn.close()
        print(f"[-] Cliente {addr} desconectado da rede.")

def start_server():
    # Mudamos para '0.0.0.0' para o servidor aceitar conexões vindas da internet (fora da sua rede local)
    HOST = '0.0.0.0' 
    PORT = 5000 

    # -----------------------------------------------------------------
    # CONFIGURAÇÃO DO TLS 1.3 (PASSO A PASSO)
    # -----------------------------------------------------------------
    print("[*] Configurando túnel TLS 1.3...")
    # Criamos um contexto SSL configurado especificamente para servidores
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Forçamos o uso do TLS 1.3 (requisito obrigatório do professor)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # Apontamos para as chaves reais que o seu Certbot gerou na sua máquina
    cert_path = "fullchain.pem"
    key_path = "privkey.pem"
    
    # O servidor carrega o certificado na memória
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    # -----------------------------------------------------------------

    # Daqui para frente, a criação do socket TCP comum continua IGUAL ao TP3
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[*] Servidor pronto e escutando na porta {PORT}...")

        while True:
            # Acontece a conexão TCP crua (igual ao TP3)
            raw_conn, addr = server_socket.accept()
            
            try:
                # AQUI ESTÁ A MÁGICA: Pegamos a conexão crua e "envelopamos" com TLS.
                # Esse comando faz o Handshake do TLS rodar automaticamente nos bastidores!
                tls_conn = context.wrap_socket(raw_conn, server_side=True)
                print(f"[+] Conexão blindada com sucesso com: {addr}")
                
                # Agora, passamos a conexão BLINDADA (tls_conn) para a sua thread antiga.
                # Note que mudamos o argumento de 'raw_conn' para 'tls_conn'
                client_thread = threading.Thread(target=handle_client, args=(tls_conn, addr))
                client_thread.daemon = True 
                client_thread.start()
                
            except ssl.SSLError as e:
                # Se alguém tentar conectar sem TLS ou com erro, o servidor joga o erro aqui e não cai
                print(f"[-] Falha no aperto de mão (Handshake) TLS com {addr}: {e}")
                raw_conn.close()

if __name__ == "__main__":
    start_server()