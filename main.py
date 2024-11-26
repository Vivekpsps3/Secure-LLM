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
import binascii
import time
from flask import Flask, request, render_template_string

num_clients = 3
file_to_send = "network_sim/encrypted.txt"
file_to_recv = "./received.txt"

#hex encoding
def hex_encode(data):
    return binascii.hexlify(data).decode()

#hex decoding
def hex_decode(data):
    return binascii.unhexlify(data)

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
def one_exchange():
    os.system("make exchange")
    return

# --- RSA Digital Signature Functions ---
class RingSignature:
    def __init__(self, keys, key_size=4096):
        self.keys = keys
        self.key_size = key_size
        self.num_keys = len(keys)  # Number of participants in the ring
        self.q = 1 << (key_size - 1)  # Derived value based on key size

    def sign(self, message, private_key, signer_index):
        self._permutate_message(message)
        signatures = [None] * self.num_keys
        secret = randint(0, self.q)
        john = hancock = self._hash(secret)
        for i in range(self.num_keys):
            idx = (signer_index + i + 1) % self.num_keys
            if idx == signer_index:
                signatures[signer_index] = self._modular_exponentiation(hancock ^ secret, private_key.d, private_key.n)
            else:
                signatures[idx] = randint(0, self.q)
                e = self._modular_exponentiation(signatures[idx], self.keys[idx].e, self.keys[idx].n)
                hancock = self._hash(hancock ^ e)
            if (idx + 1) % self.num_keys == 0 and idx != signer_index:
                john = hancock
        return [john] + signatures

    def verify(self, message, ring_signature):
        self._permutate_message(message)

        partials = []
        for i in range(len(ring_signature) - 1):
            try:
                computed_hash = self._modular_exponentiation(
                    ring_signature[i + 1], self.keys[i].e, self.keys[i].n
                )
                partials.append(computed_hash)
            except:
                pass
        result = ring_signature[0]
        for i in range(self.num_keys):
            result = self._hash(result ^ partials[i])
        return result == ring_signature[0]

    def _permutate_message(self, message):
        self.p = int(SHA256.new(message.encode()).hexdigest(), 16)

    def _hash(self, x):
        msg = f'{x}{self.p}'
        return int(SHA256.new(msg.encode()).hexdigest(), 16)

    def _modular_exponentiation(self, base, exp, mod):
        result = 1
        base = base % mod
        while exp > 0:
            if (exp % 2) == 1:
                result = (result * base) % mod
            exp = exp >> 1
            base = (base * base) % mod
        return result

def load_public_keys(num_clients):
  public_keys = []
  for i in range(1, num_clients + 1):
    filename = f"client{i}.pub"
    with open(filename, 'rb') as f:
      public_key = RSA.import_key(f.read())
    public_keys.append(public_key)
  return public_keys

def sign_message(private_key, message):
    hash_obj = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    return signature

def verify_signature(public_key, message, signature):
    hash_obj = SHA256.new(message)
    # try:
    pkcs1_15.new(public_key).verify(hash_obj, signature)
    return True
    # except (ValueError, TypeError):
    #     return False

# --- TLS Handshake Simulation ---
def load_rsa_keys(priv_path, pub_path):
    with open(priv_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    with open(pub_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key

def tls_handshake(p, g):
    # Load RSA keys
    client_priv, client_pub = load_rsa_keys("client1.priv", "client1.pub")
    server_priv, server_pub = load_rsa_keys("server.priv", "server.pub")

    # Client generates DH key pair
    client_private, client_public = dh_generate_keypair(p, g)

    public_keys = load_public_keys(num_clients)

    ring = RingSignature(public_keys)

    # Client signs the DH public key and sends it
    client_signature = ring.sign(str(client_public), client_priv, public_keys.index(client_priv.public_key()))

    write_message(client_public, client_signature[0].to_bytes(256, 'big'))

    # Server reads the message, verifies signature, and generates its own DH key pair
    client_public_received, client_signature_received = read_message()
    client_public_received = client_public

    if not ring.verify(str(client_public_received), client_signature):
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
    encoded_message = bytes(hex_encode(message), 'utf-8')
    with open(file_to_send, 'wb') as f:
        f.write(encoded_message)
        f.close()
    

    one_exchange()  # Simulate network exchange

def read_message():
    with open(file_to_recv, 'rb') as f:
        encoded_data = f.read()
        encoded_data = encoded_data.decode('utf-8')
        data = hex_decode(encoded_data)
        dh_public = int.from_bytes(data[:256])
        signature = data[256:]
    return dh_public, signature

# --- TLS Secure Communication Simulation ---
def secure_communication(aes_key, prompt):
    # Encrypt prompt using AES
    encrypted_message = aes_encrypt(aes_key, prompt)
    # Encode message to hex
    encrypted_message = hex_encode(encrypted_message)
    encrypted_message = bytes(encrypted_message, 'utf-8')
    with open(file_to_send, 'wb') as f:
        f.write(encrypted_message)
    
    one_exchange()  # Simulate network exchange

    # Read and decrypt response
    with open(file_to_recv, 'rb') as f:
        encrypted_response = f.read()
        encrypted_response = encrypted_response.decode('utf-8')
        encrypted_response = hex_decode(encrypted_response)
    response = aes_decrypt(aes_key, encrypted_response)
    return response

# Main Execution
def run(prompt):
    p = 23  # Prime number
    g = 5   # Primitive root mod 23
    
    # Perform TLS handshake to derive AES key
    aes_key = tls_handshake(p, g)

    # Example secure communication using AES-encrypted message
    server_prompt = secure_communication(aes_key, prompt)

    prompt_response = llm.get_completion(server_prompt)

    response = secure_communication(aes_key, prompt_response)

    return response

if __name__ == "__main__":

    # prompt = "What is the meaning of life?"
    # response = run(prompt)
    # print(response)

    app = Flask(__name__)

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure LLM</title>
    </head>
    <body>
        <h1>Enter your prompt</h1>
        <form method="post" action="/">
            <textarea name="prompt" rows="4" cols="50"></textarea><br>
            <input type="submit" value="Submit">
        </form>
        {% if response %}
        <h2>Response:</h2>
        <p>{{ response }}</p>
        {% endif %}
    </body>
    </html>
    """

    @app.route("/", methods=["GET", "POST"])
    def index():
        response = None
        if request.method == "POST":
            prompt = request.form["prompt"]
            response = run(prompt)
        return render_template_string(html_template, response=response)

    app.run(debug=True, host="0.0.0.0")