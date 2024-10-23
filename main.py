import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import randint
import configparser

from server import llm
from network_sim import sender as sender
from network_sim import receiver as receiver
import multiprocessing

file_to_send = "network_sim/encrypted.txt"
file_to_recv = "network_sim/recieved.txt"

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

if __name__ == "__main__":
    prompt = "What is the capital of France?"
    #encrypt the prompt
    #make up a key
    key = os.urandom(16)
    ciphertext = aes_encrypt(key, prompt)

    # print(ciphertext)
    # with open(file_to_send, "wb") as f:
    #     f.write(ciphertext)


    # Load the config file
    config_path = "network_sim/config.ini"
    cfg = configparser.RawConfigParser(allow_no_value=True)
    cfg.read(config_path)

    # Create the sender and receiver objects
    sender = sender.Sender(cfg, config_path)
    # receiver = receiver.receiver(config_path)

    # Define the sender and receiver functions
    def send_data():
        sender.send()

    def receive_data():
        receiver.receiver(config_path)

    # Create processes for sending and receiving
    sender_process = multiprocessing.Process(target=send_data)
    receiver_process = multiprocessing.Process(target=receive_data)

    # Start the processes
    sender_process.start()
    receiver_process.start()

    # Wait for both processes to complete
    sender_process.join()
    receiver_process.join()


    completion = llm.get_completion(prompt)
    print(completion)

