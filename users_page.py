import datetime
import tkinter as tk
from tkinter import messagebox
import pymongo
import login_page
import public_key_crypto as pkc
import encryption_module as em
from secrets import token_bytes


client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"]
users_collection = db['users']
messages_collection = db['messages']
keys_collection = db['keys']
# for x in messages_collection.find():
#     print("************MESSAGE**************")
#     print(x)


# Function to display the page with a list of users
def show_users_page(username):
    # Connect to MongoDB

    # Query MongoDB for all users
    all_users = users_collection.find()

    # Create GUI for displaying users
    users_window = tk.Toplevel()
    users_window.title("All Users")

    scrollbar = tk.Scrollbar(users_window)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    users_listbox = tk.Listbox(users_window, yscrollcommand=scrollbar.set)
    users_listbox.pack(fill=tk.BOTH, expand=True)

    # Add each user to the Listbox
    for user in all_users:
        user_name = user['username']
        users_listbox.insert(tk.END, user_name)

    # Configure scrollbar
    scrollbar.config(command=users_listbox.yview)

    # Function to handle click on a user
    def user_clicked(event):
        selected_index = users_listbox.curselection()
        if selected_index:
            selected_user = users_listbox.get(selected_index[0])
            # Perform actions when a user is clicked
            show_messages(selected_user, username)

    def user_double_clicked(event):
        selected_index = users_listbox.curselection()
        if selected_index:
            selected_user = users_listbox.get(selected_index[0])
            # Display a text box with a send message button
            send_message_window = tk.Toplevel()
            send_message_window.title("Send Message")

            message_entry = tk.Entry(send_message_window, width=50)
            message_entry.pack(padx=10, pady=10)

            send_button = tk.Button(send_message_window, text="Send", command=lambda: send_message(
                selected_user, message_entry.get(), username))
            send_button.pack(padx=10, pady=5)

    # Bind the double-click event to the Listbox
    users_listbox.bind("<Double-Button-1>", user_double_clicked)
    # Bind the click event to the Listbox
    users_listbox.bind("<Button-1>", user_clicked)


def show_messages(sender, recipient):
    rsa_encryption = pkc.RSAEncryption()
    print("**************sender**************")
    print(sender)
    print("**************recipient**************")
    print(recipient)
    
    # Query MongoDB for messages between sender and recipient
    # Define the query criteria
    query = {"sender": sender, "recipient": recipient}
    

    # Perform the query and sort the results by timestamp in ascending order
    chat_messages = messages_collection.find(
        query).sort("timestamp", pymongo.ASCENDING)
    print("**************chat_messages**************")

    # Create GUI for displaying messages
    messages_window = tk.Toplevel()
    messages_window.title("Messages")

    messages_textbox = tk.Text(messages_window)
    messages_textbox.pack(fill=tk.BOTH, expand=True)
    
    for x in chat_messages:
        print("**************ciphertext**************")
        print(x['ciphertext'])
        print("************** encrypted aes_key**************")
        print(x['aes_key'])
        print("**************recipient**************")
        print(recipient)
        plaintext = decrypt_message_and_key(
            x['ciphertext'], x['aes_key'], recipient,x['nonce'])
        print("**************plaintext**************")
        print(plaintext)
        messages_textbox.insert(tk.END, f"{plaintext}\n")


    messages_textbox.config(state=tk.DISABLED)



def send_message(recipient, message, username):
    # Get the public key of the recipient
    ciphertext, encrypted_AES_key,nonce = encrypt_message_and_key(
        message, recipient, sender=username)
    message_timestamp = datetime.datetime.now()
    print("********message*********")
    print(message)
    print("********ciphertext*********")
    print(ciphertext)
    print("********encrypted AES key*********")
    print(encrypted_AES_key)
    
    message = {"sender": username, "recipient": recipient, "aes_key": encrypted_AES_key,
               "ciphertext": ciphertext, "timestamp": message_timestamp , "nonce": nonce}

    # Save the encrypted message in the database
    messages_collection.insert_one(message)
    messagebox.showinfo("Success", "Message sent successfully!")


def encrypt_message_and_key(message, recipient, sender):
    rsa_encryption = pkc.RSAEncryption()
    # Get the public key of the recipient
    recipient_public_key = get_public_key(recipient)
    print("********recipient_public_key*********")
    print( recipient_public_key)
    if recipient_public_key is None:
        messagebox.showerror("Error", "Recipient not found!")
        return
    # Encrypt the message with AES
    AES_key = em.generate_AES_key()
    print("AES_key ", AES_key)
    nonce, ciphertext, tag = em.encrypt(message, AES_key)

    # Encrypt the AES_key with the recipient's public key
    rsa_encryption = pkc.RSAEncryption()
    encrypted_AES = rsa_encryption.encrypt_AES_key(
        AES_key, recipient_public_key)
    return ciphertext, encrypted_AES, nonce


def decrypt_message_and_key(ciphertext, encrypted_AES_key, recipient,nonce):
    
    
    rsa_encryption = pkc.RSAEncryption()
    # Get the private key of the recipient
    recipient_private_key = rsa_encryption.get_private_key(recipient)
    
    # Decrypt the AES_key with the recipient's private key
    decrypted_AES_key = rsa_encryption.decrypt(
        encrypted_AES_key, recipient_private_key)
    print("decrypted AES key ", decrypted_AES_key)
    # Decrypt the message with the AES key
    block_cipher = em.AES.new(decrypted_AES_key, em.AES.MODE_EAX,nonce=nonce)
    plaintext = block_cipher.decrypt(ciphertext)
    print("******** decrypted Plaintext*********")
    print(plaintext.decode("ascii"))
    return plaintext.decode("ascii")


def get_public_key(username):
    rsa_encryption = pkc.RSAEncryption()
    user_data = keys_collection.find_one({"username": username})
    if user_data is None:
        return None
    public_key = user_data['public_key']
    public_key_2 = rsa_encryption.rewind_public_key(public_key)
    return public_key_2

