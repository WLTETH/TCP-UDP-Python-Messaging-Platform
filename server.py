# This server.py will allow new connections from a client

# low priority TODO: if client has same port as another existing client, change the client port and let client know to change port (might be an easier way to ensure clients do not have same ports to begin with?)
# low priority TODO: data validation?

from socket import *
from threading import *
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

#constants
HOST = '127.0.0.1' #local ip
PORT = 12022
key = b'group22csc3002f$'

QUIT_KEYWORD = "$quit"
CONNECT_KEYWORD = "$connect"
REFRESH_KEYWORD = "$refreshList"
BUSY_KEYWORD = "$busy"
AVAILABLE_KEYWORD = "$available"

clients = {}    # Stores username:(ip, port)
client_usernames = {}   # Stores usernames with statuses; username:status

server_socket = socket(AF_INET, SOCK_STREAM) #TCP
server_socket.bind((HOST, PORT))

server_socket.listen(5) # if more than 5 connections waiting, reject new connections

print(f"Server is running on {HOST} with port {PORT}")

#function to encrypt data
def encrypt(key, plaintext):
    iv = b'$2f003csc22puorg'  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to a multiple of the block size
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

#function to decrypt data
def decrypt(key, ciphertext):
    iv = b'$2f003csc22puorg'  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data


#function to remove a user from clients and update their status in client_usernames
def offline_client(client_name):
    del clients[client_name]    
    client_usernames[client_name] = "offline"
    print(f"Client {client_name} went offline.\n\n")

#function to send messages to clients
def send_message(client_socket, message):
    client_socket.send(encrypt(key, message.encode('utf-8')))

# function to handle connecting clients and provide them with user details
def handle_client():
    # STEP 1 : get the username of the new client
    client_socket, addr = server_socket.accept() # get socket and address of incoming connection
    try:
        print(f"Connected to {addr}")
        client_message = decrypt(key, client_socket.recv(1024)).decode('utf-8') # RECEIVE: get client username, ip, udp port as string separated with #
    except socket.error:
        print(f"Error communicating with {addr}")
        return
    
    try:
        # check that client is still active (that they haven't terminated the session)
        if client_message != QUIT_KEYWORD:
            # split client info
            client_info = client_message.split("#")
            client_username = client_info[0]
            client_ip = client_info[1]
            client_port = client_info[2]

            clients[client_username] = [client_ip, client_port] # add client to dictionary

            client_usernames[client_username] = "available" # add username to list of usernames

            print(f"Client connected with username \"{client_username}\"\n") # print confirmation

            #STEP 2 : send new client confirmation that they are connected and list of available users
            send_message(client_socket, f"You are connected to the server as {client_username}") # send client confirmation

            # Command handling below:
            # CONNECT_KEYWORD = connect to a client
            # REFRESH_KEYWORD = send available clients list
            # QUIT_KEYWORD = terminate session
            # BUSY_KEYWORD = Set status to busy to prevent new user contact
            # AVAILABLE_KEYWORD = Set status to available to enable new connections

            while True:

                command_and_message = decrypt(key, client_socket.recv(1024)).decode('utf-8') # RECEIVE: get a command followed by a message, separated by :
                # e.g. "$connect:{desired_client_username}"

                if ":" in command_and_message:
                    info = command_and_message.split(":")
                    command = info[0]
                    message = info[1]
                else:
                    command = command_and_message

                if command == CONNECT_KEYWORD:
                    # STEP 4 : get the username of the client that the new client would like to speak to
                    desired_client_username = message
                    print(f"Attempting to connect {client_username} to the requested username {desired_client_username}.")
                    status = client_usernames.get(desired_client_username) #get client status

                    if status == None:
                        send_message(client_socket, f"Requested user with username {desired_client_username} does not exist.\nPlease enter a different username.")
                        status = "Not Found"
                        continue
                    
                    print(f"User {desired_client_username} has status {status}.\n")
                
                    # messages sent depending on user status
                    while desired_client_username != QUIT_KEYWORD:
                        
                        if status == "available":
                            send_message(client_socket, f"You are now connected with {desired_client_username}")

                            break # exit the loop since client is available, ready to continue
                        elif status == "busy":
                            send_message(client_socket, f"Requested user with username {desired_client_username} is busy.\nPlease enter a different username.")
                            break
                        elif status == "offline": #if user is offline
                            send_message(client_socket, f"Requested user with username {desired_client_username} is offline.\nPlease enter a different username.")
                            break
                        
                    if desired_client_username != "$quit" and status == "available":
                        # send chat details
                        client_info = clients[desired_client_username]  #retreiving username details (ip, port)
                        client_info_string = '#'.join(client_info)
                        send_message(client_socket, f"{client_info_string}") # SEND: send chat details (ip and port in string seperated by #)    
                
                    continue
                elif command == REFRESH_KEYWORD:
                    # create list of all available client usernames
                    all_client_usernames = ', '.join({i for i in client_usernames if client_usernames[i]=="available"}) # put usernames into string
                    
                    # SEND : send usernames of other clients to newly connected client
                    send_message(client_socket, f"List of available clients:\n{all_client_usernames} (Last Refreshed at {datetime.now().strftime('%H:%M')})") # SEND: send list of all available clients
                    continue
                elif command == QUIT_KEYWORD:
                    print(f"Disconnected client {client_username} from server")

                    # remove client from clients and change status to offline
                    offline_client(client_username)
                    break
                elif command == BUSY_KEYWORD:
                    client_usernames[client_username] = "busy"
                elif command == AVAILABLE_KEYWORD:
                    client_usernames[client_username] = "available"

        else:
            print("Client terminated the session.") # client did not provide username so client is not on list, no need to remove them
            client_socket.close()
    except ConnectionResetError:
        print(f"Lost connection to client \"{client_username}\"")   
        offline_client(client_username) 
while True:
    # multi-threading
    thread = Thread(target=handle_client, args=())
    thread.start()