import tkinter as tk
import socket
import threading

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

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', PORT))

def receive_messages():
    """Listen for incoming messages and display them in the chat history."""
    while True:
        message, address = sock.recvfrom(BUFFER_SIZE)
        history.config(state=tk.NORMAL)
        history.insert(tk.END, f"[{address[0]}]: {message.decode()}\n")
        history.config(state=tk.DISABLED)

def send_message():
    """Send the message to the specified IP address."""
    message = message_entry.get()
    dest_ip = ip_entry.get()
    sock.sendto(message.encode(), (dest_ip, PORT))
    message_entry.delete(0, tk.END)

# Start a thread to receive messages
threading.Thread(target=receive_messages, daemon=True).start()

# Bind the send button to send_message()
send_button.config(command=send_message)

# Function to remove the default text when the user clicks on the entry box
def on_entry_click(event):
    if message_entry.get() == "Message" or ip_entry.get() == "IP Address":
        event.widget.delete(0, "end") # delete all the text in the entry widget
        event.widget.insert(0, "") # insert blank for user input

# Bind the default text removal function to the entry boxes
message_entry.bind("<FocusIn>", on_entry_click)
ip_entry.bind("<FocusIn>", on_entry_click)

# Function to restore the default text if the user clicks away without entering anything
def on_focusout(event):
    if message_entry.get() == "":
        message_entry.insert(0, "Message")
    if ip_entry.get() == "":
        ip_entry.insert(0, "IP Address")

# Bind the default text restoration function to the entry boxes
message_entry.bind("<FocusOut>", on_focusout)
ip_entry.bind("<FocusOut>", on_focusout)

# Start the GUI event loop
root.mainloop()
