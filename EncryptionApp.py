# Author: Johann Valenteros [1]
# [1]: https://github.com/jvalenteros

import tkinter as tk
import base64
from tkinter import ttk, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Encryption/Decryption Tool")
        master.geometry("500x400")

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        self.aes_frame = ttk.Frame(self.notebook)
        self.rsa_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.aes_frame, text="AES")
        self.notebook.add(self.rsa_frame, text="RSA")

        self.setup_aes_frame()
        self.setup_rsa_frame()

    def setup_aes_frame(self):
        ttk.Label(self.aes_frame, text="Text:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.aes_text = tk.Text(self.aes_frame, height=5)
        self.aes_text.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.aes_frame, text="Key (16 bytes):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.aes_key = ttk.Entry(self.aes_frame, width=50)
        self.aes_key.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(self.aes_frame, text="Encrypt", command=self.aes_encrypt).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(self.aes_frame, text="Decrypt", command=self.aes_decrypt).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(self.aes_frame, text="Result:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.aes_result = tk.Text(self.aes_frame, height=5)
        self.aes_result.grid(row=3, column=1, padx=5, pady=5)

    def setup_rsa_frame(self):
        ttk.Label(self.rsa_frame, text="Text:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.rsa_text = tk.Text(self.rsa_frame, height=5)
        self.rsa_text.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(self.rsa_frame, text="Generate Keys", command=self.generate_rsa_keys).grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        ttk.Button(self.rsa_frame, text="Encrypt", command=self.rsa_encrypt).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(self.rsa_frame, text="Decrypt", command=self.rsa_decrypt).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(self.rsa_frame, text="Result:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.rsa_result = tk.Text(self.rsa_frame, height=5)
        self.rsa_result.grid(row=3, column=1, padx=5, pady=5)

        self.public_key = None
        self.private_key = None

    def aes_encrypt(self):
        text = self.aes_text.get("1.0", "end-1c").encode()
        key = self.aes_key.get().encode()
        
        if len(key) != 16:
            messagebox.showerror("Failed", "AES key must be 16 bytes long")
            return

        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(text)

        encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
        self.aes_result.delete("1.0", "end")
        self.aes_result.insert("1.0", encrypted)

    def aes_decrypt(self):
        encrypted = self.aes_text.get("1.0", "end-1c")
        key = self.aes_key.get().encode()

        if len(key) != 16:
            messagebox.showerror("Failed", "AES key must be 16 bytes long")
            return

        encrypted = base64.b64decode(encrypted)
        nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]

        cipher = AES.new(key, AES.MODE_EAX, nonce)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            self.aes_result.delete("1.0", "end")
            self.aes_result.insert("1.0", decrypted.decode())
        except ValueError:
            messagebox.showerror("Failed", "Decryption failed. Invalid key or corrupted message.")

    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()
        messagebox.showinfo("Success", "RSA keys generated successfully")

    def rsa_encrypt(self):
        if not self.public_key:
            messagebox.showerror("Failed", "Please generate RSA keys first")
            return

        text = self.rsa_text.get("1.0", "end-1c").encode()
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted = cipher.encrypt(text)

        encrypted_b64 = base64.b64encode(encrypted).decode()
        self.rsa_result.delete("1.0", "end")
        self.rsa_result.insert("1.0", encrypted_b64)

    def rsa_decrypt(self):
        if not self.private_key:
            messagebox.showerror("Failed", "Please generate RSA keys first")
            return

        encrypted_b64 = self.rsa_text.get("1.0", "end-1c")
        encrypted = base64.b64decode(encrypted_b64)

        cipher = PKCS1_OAEP.new(self.private_key)
        try:
            decrypted = cipher.decrypt(encrypted)
            self.rsa_result.delete("1.0", "end")
            self.rsa_result.insert("1.0", decrypted.decode())
        except ValueError:
            messagebox.showerror("Failed", "Decryption failed. Invalid key or corrupted message.")

        
root = tk.Tk()
app = EncryptionApp(root)
root.mainloop()