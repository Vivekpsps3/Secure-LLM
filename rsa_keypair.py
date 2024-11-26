from Crypto.PublicKey import RSA

# Generate a 4096-bit RSA key pair
key = RSA.generate(4096)
key2 = RSA.generate(4096)

# Save the private for the server
with open("server.priv", "wb") as f:
    f.write(key.export_key())

# Save the public key for the server
with open("server.pub", "wb") as f:
    f.write(key.publickey().export_key())

# Save the private for the client
with open("client1.priv", "wb") as f:
    f.write(key2.export_key())

# Save the public key for the client
with open("client1.pub", "wb") as f:
    f.write(key2.publickey().export_key())

