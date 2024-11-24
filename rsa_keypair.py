from Crypto.PublicKey import RSA
import sys

# Generate a 4096-bit RSA key pair
key = RSA.generate(4096)

# Save the private for the server
with open("server.priv", "wb") as f:
    f.write(key.export_key())

# Save the public key for the server
with open("server.pub", "wb") as f:
    f.write(key.publickey().export_key())

clients = 3
if len(sys.argv) > 1:
    clients = int(sys.argv[1])
for i in range(clients):
    key = RSA.generate(4096)
    # Save the private for the client
    with open(f"client{i}.priv", "wb") as f:
        f.write(key.export_key())

    # Save the public key for the client
    with open(f"client{i}.pub", "wb") as f:
        f.write(key.publickey().export_key())

