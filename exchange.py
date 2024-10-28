import multiprocessing
import time
from network_sim import sender as sender
from network_sim import receiver as receiver
import configparser
import os


file_to_send = "network_sim/encrypted.txt"
file_to_recv = "./received.txt"
# Load the config file
config_path = "network_sim/config.ini"
cfg = configparser.RawConfigParser(allow_no_value=True)
cfg.read(config_path)

# Create the sender object
sender = sender.Sender(cfg, config_path)

def emulated_network():
    os.system("cd Emulator && make all")

def send_data():
    sender.send()

def receive_data():
    receiver.receiver(config_path)

def one_exchange():
    # Start the emulated network as a separate process
    network_process = multiprocessing.Process(target=emulated_network)
    network_process.start()

    
    # Create processes for sending and receiving
    sender_process = multiprocessing.Process(target=send_data)
    receiver_process = multiprocessing.Process(target=receive_data)

    # Start the processes
    sender_process.start()
    receiver_process.start()

    # Wait for both processes to complete with a timeout of 5 seconds
    sender_process.join(5)
    receiver_process.join(5)
    network_process.terminate()

    # Terminate the processes if they are still running after the timeout
    if sender_process.is_alive():
        sender_process.terminate()
    if receiver_process.is_alive():
        receiver_process.terminate()

    #sleep for 1 second to allow the receiver to finish
    time.sleep(1)

    return True


if __name__ == "__main__":
    one_exchange()
    print("Exchange completed")