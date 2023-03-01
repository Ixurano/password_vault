import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import tkinter
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


backend = default_backend()
salt = b'2655'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend,
)
encryptionKey = 0


def encrypt(message: bytes, key: bytes,) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes,) -> bytes:
    return Fernet(token).decrypt(message)


# Database Code
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL,
note TEXT NOT NULL);
""")

# Create PopUps


def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer


# Initiate Window
window = Tk()

window.title("Password Vault")


def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def firstScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")

    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.pack()

    txt1 = Entry(window, width=30, show="*")
    txt1.pack()

    lbl2 = Label(window)
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(
                kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?)"""
            cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lbl2.config(text="Passwords do not match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=10)


def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")

    lbl = Label(window, text="Save this key to recover the account")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.pack()

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text="Copy Key", command=copyKey)
    btn.pack(pady=10)

    def done():
        passwordVault()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=10)


def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")

    lbl = Label(window, text="Enter Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute(
            'SELECT * FROM masterpassword WHERE id=1 AND recoveryKey=?', [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            firstScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong recovery key")

    btn = Button(window, text="Check key", command=checkRecoveryKey)
    btn.pack(pady=10)


def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(
            kdf.derive(txt.get().encode()))
        cursor.execute(
            "SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()

        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong password")

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=10)


def passwordVault():
    # destroys the login window if logged in to not overlapp
    for widget in window.winfo_children():
        widget.destroy()
    
    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        text4 = "Note"

        website = encrypt(popUp(text1).encode(), encryptionKey)
        username = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(popUp(text3).encode(), encryptionKey)
        note = encrypt(popUp(text4).encode(), encryptionKey)
        insert_fields = """
        INSERT INTO vault(website,username,password,note)
        VALUES(?, ?, ?, ?)
        """

        cursor.execute(insert_fields, (website, username, password, note))
        db.commit()

        passwordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    def copy(pswd):
        window.clipboard_clear()
        window.clipboard_append(pswd)
        
    
    window.geometry("900x350")

    lbl = Label(window, text="Password Vault")
    lbl.grid(column=1, columnspan=2)

    btn = Button(window, text="+", command=addEntry)
    btn.grid(column=1, columnspan=2)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)
    
    
    lbl = Label(window, text="Note")
    lbl.grid(row=2, column=4, padx=80)

    
    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()
            if len(array) >= 1:

                lbl1 = Label(window, text=(
                    decrypt(array[i][1],encryptionKey)), font=("Helvetica", 12))
                lbl1.grid(column=0, row=i+3)
                lbl1 = Label(window, text=(
                    decrypt(array[i][2],encryptionKey)), font=("Helvetica", 12))
                lbl1.grid(column=1, row=i + 3)
                #password
                lbl1 = Label(window, text=(
                    decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
                lbl1.grid(column=2, row=i + 3)
                #Copy-btn here
                btnCopy = Button(window, text="Copy", command=copy(decrypt(array[i][3], encryptionKey)))
                btnCopy.grid(column=3, row=i+3)
                
                lbl1 = Label(window, text=(
                    decrypt(array[i][4], encryptionKey)), font=("Helvetica", 12))
                lbl1.grid(column=4, row=i + 3)

                btn = Button(window, text="Delete",
                             command=partial(removeEntry, array[i][0]))
                btn.grid(column=5, row=i+3, pady=10)

                i = i+1

                cursor.execute("SELECT * FROM vault")
                if(len(cursor.fetchall()) <= i):
                    break
            else:
                break


cursor.execute("SELECT * FROM masterpassword")

if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()
