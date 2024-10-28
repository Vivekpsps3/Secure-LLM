import os
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from random import randint
import configparser
from server import llm
from network_sim import sender as sender
from network_sim import receiver as receiver
import multiprocessing
import base64



file_to_send = "network_sim/encrypted.txt"
file_to_recv = "./received.txt"
# Load the config file
config_path = "network_sim/config.ini"
cfg = configparser.RawConfigParser(allow_no_value=True)
cfg.read(config_path)

# Create the sender object
sender = sender.Sender(cfg, config_path)

# --- Diffie-Hellman Functions ---
def dh_generate_keypair(p, g):
    private_key = randint(1, p-1)
    public_key = mod_exp(g, private_key, p)
    return private_key, public_key

def dh_compute_shared_secret(public_key, private_key, p):
    return mod_exp(public_key, private_key, p)

def derive_aes_key(shared_secret):
    # Derive a 128-bit AES key using SHA1 and truncate it
    sha1 = hashlib.sha1(str(shared_secret).encode()).digest()
    return sha1[:16]

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:  # If exp is odd, multiply base with result
            result = (result * base) % mod
        exp = exp >> 1  # exp = exp // 2
        base = (base * base) % mod  # Square the base
    return result

# --- AES CBC Functions ---
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)  # Generate random 128-bit IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext  # Append IV to the ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]  # Extract IV from the beginning
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


# --- Communication Functions ---
def send_data():
    sender.send()

def receive_data():
    receiver.receiver(config_path)

def one_exchange():
    # Create processes for sending and receiving
    sender_process = multiprocessing.Process(target=send_data)
    receiver_process = multiprocessing.Process(target=receive_data)

    # Start the processes
    sender_process.start()
    receiver_process.start()

    # Wait for both processes to complete
    sender_process.join()
    receiver_process.join()

# --- RSA Digital Signature Functions ---
def sign_message(private_key, message):
    hash_obj = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    return signature

def verify_signature(public_key, message, signature):
    hash_obj = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

# --- TLS Handshake Simulation ---
def load_rsa_keys(priv_path, pub_path):
    with open(priv_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    with open(pub_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key

def tls_handshake(p, g):
    # Load RSA keys
    client_priv, client_pub = load_rsa_keys("client.priv", "client.pub")
    server_priv, server_pub = load_rsa_keys("server.priv", "server.pub")

    # Client generates DH key pair
    client_private, client_public = dh_generate_keypair(p, g)

    # Client signs the DH public key and sends it
    client_signature = sign_message(client_priv, str(client_public).encode())
    write_message(client_public, client_signature)

    # Server reads the message, verifies signature, and generates its own DH key pair
    client_public_received, client_signature_received = read_message()

    if not verify_signature(client_pub, str(client_public_received).encode(), client_signature_received):
        raise ValueError("Client's signature verification failed")

    server_private, server_public = dh_generate_keypair(p, g)
    shared_secret = dh_compute_shared_secret(client_public_received, server_private, p)

    # Server signs its DH public key and sends it back
    server_signature = sign_message(server_priv, str(server_public).encode())
    write_message(server_public, server_signature)

    # Client verifies server's signature and computes shared secret
    server_public_received, server_signature_received = read_message()
    if not verify_signature(server_pub, str(server_public_received).encode(), server_signature_received):
        raise ValueError("Server's signature verification failed")
    
    shared_secret_client = dh_compute_shared_secret(server_public_received, client_private, p)
    assert shared_secret == shared_secret_client, "Shared secrets do not match"
    
    aes_key = derive_aes_key(shared_secret)
    return aes_key

# --- Message Read/Write Functions ---
def write_message(dh_public, signature):
    message = dh_public.to_bytes(256) + signature
    encoded_message = base64.b64encode(message)
    with open(file_to_send, 'wb') as f:
        f.write(encoded_message)

    # one_exchange()  # Simulate network exchange

def read_message():
    with open(file_to_send, 'rb') as f:
        encoded_data = f.read()
        data = base64.b64decode(encoded_data)
        dh_public = int.from_bytes(data[:256])
        signature = data[256:]
    return dh_public, signature

# --- TLS Secure Communication Simulation ---
def secure_communication(aes_key, prompt):
    # Encrypt prompt using AES
    encrypted_message = aes_encrypt(aes_key, prompt)
    with open(file_to_send, 'wb') as f:
        f.write(encrypted_message)
    
    # one_exchange()  # Simulate network exchange

    # Read and decrypt response
    with open(file_to_send, 'rb') as f:
        encrypted_response = f.read()
    response = aes_decrypt(aes_key, encrypted_response)
    return response

# Main Execution
if __name__ == "__main__":
    p = 23  # Prime number
    g = 5   # Primitive root mod 23
    
    # Perform TLS handshake to derive AES key
    aes_key = tls_handshake(p, g)

    # Example secure communication using AES-encrypted message
    prompt = "Your prompt here."
    response = secure_communication(aes_key, prompt)
    print("Received response:", response)
