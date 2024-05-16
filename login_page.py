import tkinter as tk
from tkinter import messagebox
import public_key_crypto as pkc
import pymongo
import users_page
import hashing as hs

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"]
users_collection = db['users']
keys_collection = db['keys']
messages_collection = db['messages']

#print the keys collection
print(keys_collection)
for x in keys_collection.find():
    print(x)


# Function to hash the password
def hash_password(password):
    hashing_algorithm = hs.SHA256Hash()
    hashing_algorithm.update(password.encode())
    hashed_password = hashing_algorithm.hexdigest()
    return hashed_password

# Function to generate RSA keys for a user, using the algorithm in public_key_crypto.py from last phase
def generate_keys(username):
    rsa_encryption = pkc.RSAEncryption()
    public_key, private_key = rsa_encryption.generate_keys(username=username)
    return public_key, private_key

# Function to insert user data into the database
def insert_data(username, hashed_password, public_key):
    users_collection.insert_one({"username": username, "password": hashed_password})
    keys_collection.insert_one({"username": username, "public_key": public_key.save_pkcs1().decode('ascii')})

# Function to create the login GUI
def create_login_gui(root):
    frame = tk.Frame(root)
    frame.pack(padx=20, pady=20)

    username_label = tk.Label(frame, text="Username:")
    username_label.grid(row=0, column=0, padx=5, pady=5)
    username_entry = tk.Entry(frame, width=30)
    username_entry.grid(row=0, column=1, padx=5, pady=5)

    password_label = tk.Label(frame, text="Password:")
    password_label.grid(row=1, column=0, padx=5, pady=5)
    password_entry = tk.Entry(frame, width=30, show="*")
    password_entry.grid(row=1, column=1, padx=5, pady=5)

    login_button = tk.Button(frame, text="Login", command=lambda: login(username_entry, password_entry), width=20)
    login_button.grid(row=2, columnspan=2, pady=10)

# Function to handle login
def login(username_entry, password_entry):
    username = username_entry.get()
    password = password_entry.get()
    hashed_password = hash_password(password)

    user_data = users_collection.find_one({"username": username})

    if user_data is None:
        # Username does not exist, register the user
        public_key, _ = generate_keys(username)
        insert_data(username, hashed_password, public_key)
        messagebox.showinfo("Success", "User registered successfully!")
    else:
        if user_data["password"] == hashed_password:
            # Username and password match
            messagebox.showinfo("Success", "Login successful!")
            users_page.show_users_page(username)  # Redirect to the user page
        else:
            # Wrong password
            messagebox.showerror("Error", "Wrong password!")

    # Clear password entry
    password_entry.delete(0, tk.END)

