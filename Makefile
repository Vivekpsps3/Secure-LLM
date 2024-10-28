.PHONY: rsa
RSA = rsa_keypair.py

rsa:
	python3 $(RSA)

test:
	python3 main.py
diff:
	diff -u received.txt ./network_sim/encrypted.txt

exchange:
	python3 exchange.py
	diff -u received.txt ./network_sim/encrypted.txt