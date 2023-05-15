import tkinter as tk
import socket
import threading
import time
import random

# Constants
PORT = 5000
BUFFER_SIZE = 1024

# Get the user's IP address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
IP = s.getsockname()[0]
s.close()

# Create the GUI
root = tk.Tk()
root.title(f"UDP Chat - {IP}")

# Create a Text widget to display chat history
history = tk.Text(root, state=tk.DISABLED)
history.pack(expand=True, fill=tk.BOTH)

# Create an Entry widget for entering messages
message_entry = tk.Entry(root, width=50)
message_entry.insert(0, "Message")
message_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

# Create a button to send messages
send_button = tk.Button(root, text="Send")
send_button.pack(side=tk.RIGHT)

# Create an Entry widget for entering the IP to chat with
ip_entry = tk.Entry(root, width=20)
ip_entry.insert(0, "IP Address")
ip_entry.pack(side=tk.TOP, fill=tk.X)

# Create an Entry widget for entering the key
key_entry = tk.Entry(root, width=20)
key_entry.insert(0, "Key")
key_entry.pack(side=tk.TOP, fill=tk.X)


# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', PORT))



#def generate_key(length):
#    """Generate a random key of the specified length."""
#    return bytes(random.randint(0, 255) for _ in range(length))

def generate_key_str(length):
    """Generate a random key string of specified length."""
    key = ""
    for i in range(length):
        key += chr(random.randint(0, 255))
    return key

# Create a button to generate a random key
generate_key_button = tk.Button(root, text="Generate Key")

# Function to generate a random key and insert it into the key field
def generate_key():
    key = generate_key_str(200)
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key)

# Bind the generate_key function to the button
generate_key_button.config(command=generate_key)

# Pack the button and key field next to each other
generate_key_button.pack(side=tk.LEFT)
key_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)



def encrypt(message, key):
    """Encrypt a message using the One Time Pad cipher with bitwise XOR."""
    message = message[:200].ljust(200)  # Truncate or pad message to 200 characters
    key = key[:200].ljust(200)  # Truncate or pad key to 200 characters
    # Convert the message and key to lists of ASCII codes
    message_codes = [ord(c) for c in message]
    key_codes = [ord(c) for c in key]
    # Perform bitwise XOR on each ASCII code pair
    encrypted_codes = [m ^ k for m, k in zip(message_codes, key_codes)]
    # Convert the encrypted ASCII codes back to a string
    encrypted_message = ''.join(chr(c) for c in encrypted_codes)
    return encrypted_message

def decrypt(encrypted_message, key):
    """Decrypt a message encrypted with the One Time Pad cipher with bitwise XOR."""
    # Convert the encrypted message and key to lists of ASCII codes
    encrypted_codes = [ord(c) for c in encrypted_message]
    key_codes = [ord(c) for c in key]
    # Perform bitwise XOR on each ASCII code pair
    decrypted_codes = [e ^ k for e, k in zip(encrypted_codes, key_codes)]
    # Convert the decrypted ASCII codes back to a string
    decrypted_message = ''.join(chr(c) for c in decrypted_codes)
    return decrypted_message.strip()  # Remove any trailing whitespace


def receive_messages():
    """Listen for incoming messages and display them in the chat history."""
    while True:
        message, address = sock.recvfrom(BUFFER_SIZE)
        timestamp = time.strftime("%H:%M:%S")
        
        # Decrypt the incoming message using the key in the "key" box
        key = key_entry.get()
        message = message.decode()[:200]  # Truncate message to 200 characters
        message = message.ljust(200)     # Pad message with spaces to length 200
        decrypted_message = decrypt(message, key)
        
        history.config(state=tk.NORMAL)
        history.insert(tk.END, f"[{address[0]}] {timestamp}: {decrypted_message}\n")
        history.config(state=tk.DISABLED)


def send_message():
    """Send the encrypted message to the specified IP address."""
    message = message_entry.get()
    dest_ip = ip_entry.get()
    key = key_entry.get()
    encrypted = encrypt(message, key)
    sock.sendto(encrypted.encode(), (dest_ip, PORT))
    message_entry.delete(0, tk.END)
    timestamp = time.strftime("%H:%M:%S")
    history.config(state=tk.NORMAL)
    history.insert(tk.END, f"[You] {timestamp}: {message}\n")
    history.config(state=tk.DISABLED)




# Start a thread to receive messages
threading.Thread(target=receive_messages, daemon=True).start()

# Bind the send button to send_message()
send_button.config(command=send_message)

# Function to remove the default text when the user clicks on the entry box
def on_entry_click(event):
    widget = event.widget
    if widget.get() == "Message" and widget == widget.focus_get():
        widget.delete(0, "end") # delete all the text in the entry widget
        widget.insert(0, "") # insert blank for user input
    elif widget.get() == "IP Address" and widget == widget.focus_get():
        widget.delete(0, "end") # delete all the text in the entry widget
        widget.insert(0, "") # insert blank for user input
    elif widget.get() == "Key" and widget == widget.focus_get():
        widget.delete(0, "end") # delete all the text in the entry widget
        widget.insert(0, "") # insert blank for user input

# Bind the default text removal function to the entry boxes
message_entry.bind("<FocusIn>", on_entry_click)
ip_entry.bind("<FocusIn>", on_entry_click)
key_entry.bind("<FocusIn>", on_entry_click)

# Function to restore the default text if the user clicks away without entering anything
def on_focusout(event):
    if message_entry.get() == "":
        message_entry.insert(0, "Message")
    if ip_entry.get() == "":
        ip_entry.insert(0, "IP Address")
    if key_entry.get() == "":
        key_entry.insert(0, "Key")

# Bind the default text restoration function to the entry boxes
message_entry.bind("<FocusOut>", on_focusout)
ip_entry.bind("<FocusOut>", on_focusout)
key_entry.bind("<FocusOut>", on_focusout)

# Start the GUI event loop
root.mainloop()
