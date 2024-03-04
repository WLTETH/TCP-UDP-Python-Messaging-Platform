import socket
from datetime import datetime
import random
import threading
import signal
import sys
import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from colorama import Back, Fore, Style, init

init()

# signal handler to let server know when client leaves using ctrl+C
def signal_handler(sig, frame):
    client_quit()

signal.signal(signal.SIGINT, signal_handler)

key = b'group22csc3002f$' #encryption key

def encrypt(key, plaintext):
    iv = b'$2f003csc22puorg'  # initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # pad the plaintext to multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

def decrypt(key, ciphertext):
    iv = b'$2f003csc22puorg'  # initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # remove padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data

# let the server know to remove the client from list of clients
def client_quit():
    print("Session closed or Ctrl+C has been pressed. Cleaning up...\n\nPlease reconnect to the server when you wish to chat again.")
    client_socket.send(encrypt(key, "$quit".encode('utf-8'))) # SENDS: keyword/command that indiciates client is done (string)
    client_socket.close()
    sys.exit(0)

receiving = False

saved_messages = [] # messages that need to be reprinted when terminal refreshes
accept_chats = [] # clients the user has accepted

state = "" # initializing the global state variable to be used to know what menu to reprint when terminal refreshes


def refresh_terminal():
    os.system('cls' if os.name == 'nt' else 'clear') # clear terminal, credit: https://stackoverflow.com/questions/2084508/clear-the-terminal-in-python

    global saved_messages # access saved_messages array

    for m in saved_messages: # print saved messages
        print(m)

    global state

    print_state() # print the menu the user was busy with

def refresh_terminal_no_print():
    os.system('cls' if os.name == 'nt' else 'clear') # clear terminal, credit: https://stackoverflow.com/questions/2084508/clear-the-terminal-in-python

    global saved_messages # access saved_messages array

    for m in saved_messages: # print saved messages
        print(m)

# send messages to another client/peer
def send_message():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    global state
    state = "\nEnter a message to send (or $home to exit): " # save the state for refreshing later

    refresh_terminal()

    while True:
        state = "\nEnter a message to send (or $home to exit): " # save the state for refreshing later
        time.sleep(0.1)
        message_to_send = input() # get message to send from user

        if message_to_send == "$quit":
            client_quit() # let server know we are quitting
            break
        elif message_to_send == "$home":
            refresh_terminal() 
            break # stop sending messages
        elif message_to_send.upper() == "Y" or message_to_send.upper() == "YES":
            continue
        elif message_to_send == "":
            pass
        else:
            msg_to_send = message_to_send
            message_to_send = f"{username}#{message_to_send}" # add username to message_to_send
            udp_socket.sendto(encrypt(key, message_to_send.encode()), (connect_to_ip, connect_to_port)) # send encrypted message to peer
            saved_messages.append(f"\n{Fore.LIGHTYELLOW_EX}({datetime.now().strftime('%d/%m/%Y %H:%M:%S')}){Style.RESET_ALL} {Fore.CYAN}You > {username_to_connect_to}:{Style.RESET_ALL} {Fore.WHITE}{msg_to_send}{Style.RESET_ALL}")
            refresh_terminal()

    udp_socket.close()

def receive_from_server():
    msg = decrypt(key, client_socket.recv(1024)).decode('utf-8')
    return msg

def send_to_server(msg_to_send):
    client_socket.send(encrypt(key, f"{msg_to_send}".encode('utf-8')))

# ask server for updated list of available users
def refresh():
    send_to_server(REFRESH_KEYWORD) # SENDS : command to get list of available users
    client_list = f"{Fore.CYAN}{receive_from_server()}{Style.RESET_ALL}" # RECEIVES : gets client list

    if len(saved_messages) > 0: # if this is not the first refresh, replace the previous refresh in the saved messages array
        saved_messages[0] = client_list
    else:
        saved_messages.append(client_list) # this is the first refresh, so save it to the first element of the saved messages array

    return client_list

# receive messages from other clients
def receive_message():
    accept = False
    udp_socket_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket_receive.bind((CLIENT_IP, int(CLIENT_PORT)))

    while True:
        encrypted_data, addr = udp_socket_receive.recvfrom(1024)
        decrypted_data = decrypt(key, encrypted_data)

        received_message_info = decrypted_data.split(b"#")  # split username and message

        sender_username = received_message_info[0].decode('utf-8')  # get username
        received_message = received_message_info[1].decode('utf-8')  # get message

        if sender_username not in accept_chats: # check if client has already been accepted by this user
            print(f"\n\n{Back.MAGENTA}{Fore.WHITE}Incoming message - press enter to continue...{Style.RESET_ALL}") # work around to stop the show_menu() input

            accept_choice = input(f"{Fore.GREEN}{sender_username}{Style.RESET_ALL} {Fore.YELLOW}would like to send you a message. [Y]es / [N]o to accept: {Style.RESET_ALL}")
            if accept_choice.upper() == "Y" or accept_choice.upper() == "YES":
                accept = True

            if accept:
                # add message to saved messages, will be printed at the end of this function
                saved_messages.append(f"\n{Fore.LIGHTYELLOW_EX}({datetime.now().strftime('%d/%m/%Y %H:%M:%S')}){Style.RESET_ALL} {Fore.CYAN}{sender_username} > You:{Style.RESET_ALL} {Fore.WHITE}{received_message}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Message declined.{Style.RESET_ALL}\n")

            accept_chats.append(sender_username)
        else:
            saved_messages.append(f"\n{Fore.LIGHTYELLOW_EX}({datetime.now().strftime('%d/%m/%Y %H:%M:%S')}){Style.RESET_ALL} {Fore.CYAN}{sender_username} > You:{Style.RESET_ALL} {Fore.WHITE}{received_message}{Style.RESET_ALL}")

        refresh_terminal() # declutter the terminal, by doing this we can show the new messages at the top

# get the menu currently in use and print it out
def print_state():
    global state 
    print(state)

# let user decide what to do
def show_menu():
    # Prompt the user for input
    prompt = "\nPlease select an option to continue:\n\n" \
             "(1) Refresh active user list\n" \
             "(2) Send a message to an active user\n" \
             "(3) Change online status\n" \
             "(4) Quit\n\nOption: "
    option = input(prompt)

    global state
    state = prompt # set the current menu being used so it can be reprinted when the terminal refreshes

    return option

# constants
QUIT_KEYWORD = "$quit"
LEAVE_KEYWORD = "$home"
CONNECT_KEYWORD = "$connect"
REFRESH_KEYWORD = "$refreshList"

SERVER_HOST = '127.0.0.1' # host ip of server
SERVER_PORT = 12022 # port of server

# CLIENT_IP = socket.gethostbyname(socket.gethostname()) # get private IP of pc (DOES NOT WORK ON VMs) # can enable this if you are not on a VM
CLIENT_IP = '127.0.0.1' # client ip of server
CLIENT_PORT = str(random.randint(49152, 65535)) # random available port to use for P2P UDP connections

# connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

# get username from user and send to server
username = input("Enter your desired username: ")

# check for $quit to see if we must indicate this to server
if username != "$quit":
    client_info = f"{username}#{CLIENT_IP}#{CLIENT_PORT}"
    send_to_server(client_info) # SENDS: client username, ip, port as string seperated by # (e.g. "user#127.0.0.1#8000")
else:
    client_quit()

# print confirmation
msg = receive_from_server()
print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}\nTo quit, enter $quit at any time\n") # RECEIVES: confirmation (string)

print(refresh())

saved_messages.append(f"Your current status is: {Back.GREEN}{Fore.WHITE}AVAILABLE{Style.RESET_ALL}")

saved_messages.append(f"{Fore.GREEN}{msg}{Style.RESET_ALL}\n\nTo quit, enter $quit at any time\n{Fore.CYAN}New Messages:{Style.RESET_ALL}")

receiving = True
receive_thread = threading.Thread(target=receive_message) 
receive_thread.start() # start thread for receiving messages

# main client loop
while True:
    time.sleep(0.1) # rest to allow the receiving thread a chance to ask for input

    option = show_menu()

    # 1 : refresh list of active users
    # 2 : chat to another user
    # 3 : change status
    # 4 : quit

    if option == "1":
        refresh()
        refresh_terminal_no_print()
    elif option == "2":
        while True:
            refresh_terminal()

            state = "\nEnter the username of who you would like to connect to (or $home to return home): " # store prompt to be reprinted if a message is received
            time.sleep(0.1)
            username_to_connect_to = input(state) # get username that user wants to connect to

            # check if user wants to go back to main menu
            if username_to_connect_to == "$home":
                refresh_terminal()
                break

            refresh() # refresh active user list incase someone just came online

            if username_to_connect_to.upper() == "YES" or username_to_connect_to.upper() == "Y" or username_to_connect_to == "": # the input will be "Y" if a user accepts a message request, we should ignore this and reloop
                continue
            elif username_to_connect_to not in saved_messages[0]:
                print("User does not exist or is busy. Please try again\n")
                continue
            elif username != "$quit":
                send_to_server(f"{CONNECT_KEYWORD}:{username_to_connect_to}") # SENDS: username that client wants to speak to (string)
            elif username == "$quit":
                client_quit()
                break
            
            # RECEIVES: confirmation that user is online (string)
            conf = receive_from_server()

            while True:
                if "connected" in conf:
                    print(conf)
                elif "busy" in conf:
                    print(conf)
                    break
                elif "offline" in conf:
                    print(conf)
                    break
                elif "does not exist" in conf:
                    print(conf)
                    break
                else:
                    print("Fatal error! Please try again later.\n")
                    print(conf)
                    break
            
                # sort info of other peer
                other_client_info_string = receive_from_server() # RECEIVES: IP and PORT of username that client wants to speak to as string seperated by # (e.g. "127.0.0.1#8000")
                other_client_info = other_client_info_string.split("#") # split up ip and port
                connect_to_ip = other_client_info[0] #udp ip
                connect_to_port = int(other_client_info[1]) #udp port

                # start thread for sending messages
                send_message()
                break
    elif option == "3":
        while True:
            # ask user what status they want to be set as
            state = f"{Fore.LIGHTYELLOW_EX}What would you like to change your status to?\n\n(1) Available (2) Busy{Style.RESET_ALL}\n"
            time.sleep(0.1)
            status_choice = input(state)

            if status_choice == "1":
                status_choice = "$available"
                status_msg = f"Your current status is: {Back.GREEN}{Fore.WHITE}AVAILABLE{Style.RESET_ALL}"
                break
            elif status_choice == "2":
                status_choice = "$busy"
                status_msg = f"Your status current status is: {Back.RED}{Fore.WHITE}BUSY{Style.RESET_ALL}"
                break
            elif status_choice.upper() == "YES" or status_choice.upper() == "Y": # the input will be "Y" if a user accepts a message request, we should ignore this and reloop
                refresh_terminal()

        # SENDS: tell server to change status to other clients
        send_to_server(status_choice)
        print(status_msg) # display confirmation to this client
        saved_messages[1] = status_msg # replace the previous saved status
    elif option == "4":
        client_quit()
        break
    elif option.upper() == "YES" or option.upper() == "Y": # the input will be "Y" if a user accepts a message request, we should ignore this and reloop
        refresh_terminal()

# Wait for threads to finish
if receiving:
    receive_thread.join()