import tkinter as tk

import pymongo
import login_page

def main():
    
    #connect to the database and print the key collection
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    
    
    root = tk.Tk()
    root.title("Login")
    root.geometry("400x200")

    login_page.create_login_gui(root)

    root.mainloop()

if __name__ == "__main__":
    main()
