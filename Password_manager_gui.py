import base64
import os
import secrets
import string
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_FILE = "key.key"
CHECK_FILE = "check.key"
PASSWORD_FILE = "passwords.txt"


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def get_or_create_salt() -> bytes:
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt


def verify_master_password(fer: Fernet) -> bool:
    if not os.path.exists(CHECK_FILE):
        token = fer.encrypt(b"check")
        with open(CHECK_FILE, "wb") as f:
            f.write(token)
        return True

    with open(CHECK_FILE, "rb") as f:
        token = f.read()
    try:
        fer.decrypt(token)
        return True
    except InvalidToken:
        return False


def load_entries():
    if not os.path.exists(PASSWORD_FILE):
        return []
    entries = []
    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        for line in f:
            data = line.strip()
            if not data:
                continue
            try:
                name, token_text = data.split("|", 1)
                entries.append((name, token_text))
            except ValueError:
                continue
    return entries


def save_entries(entries):
    with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
        for name, token_text in entries:
            f.write(name + "|" + token_text + "\n")


def gen_password(length: int) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


class LoginDialog(simpledialog.Dialog):
    def body(self, master):
        tk.Label(master, text="Enter master password:").grid(row=0, column=0, padx=5, pady=5)
        self.entry = tk.Entry(master, show="*")
        self.entry.grid(row=0, column=1, padx=5, pady=5)
        return self.entry

    def apply(self):
        self.result = self.entry.get()


class AddEntryDialog(simpledialog.Dialog):
    def body(self, master):
        tk.Label(master, text="Username / Website:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.name_entry = tk.Entry(master, width=30)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(master, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.pwd_entry = tk.Entry(master, width=30, show="*")
        self.pwd_entry.grid(row=1, column=1, padx=5, pady=5)

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(
            master, text="Show password", variable=self.show_var, command=self.toggle_show
        ).grid(row=2, column=1, sticky="w")

        tk.Label(master, text="Generate length:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.length_entry = tk.Entry(master, width=6)
        self.length_entry.insert(0, "16")
        self.length_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        tk.Button(master, text="Generate", command=self.generate).grid(row=4, column=1, sticky="w", pady=5)

        return self.name_entry

    def toggle_show(self):
        self.pwd_entry.config(show="" if self.show_var.get() else "*")

    def generate(self):
        try:
            length = int(self.length_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Length must be a number.")
            return
        pwd = gen_password(length)
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, pwd)
        self.show_var.set(True)
        self.toggle_show()

    def apply(self):
        self.result = (self.name_entry.get().strip(), self.pwd_entry.get())


class PasswordManagerApp(tk.Tk):
    def __init__(self, fer: Fernet):
        super().__init__()
        self.fer = fer
        self.title("Password Manager")
        self.geometry("520x400")
        self.resizable(False, False)

        self.entries = load_entries()

        self.tree = ttk.Treeview(self, columns=("name",), show="headings", selectmode="browse")
        self.tree.heading("name", text="Username / Website")
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_list()

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Add", width=10, command=self.add_entry).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="View", width=10, command=self.view_entry).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Copy", width=10, command=self.copy_entry).grid(row=0, column=2, padx=5)
        tk.Button(btn_frame, text="Delete", width=10, command=self.delete_entry).grid(row=0, column=3, padx=5)
        tk.Button(btn_frame, text="Clear All", width=10, command=self.clear_all).grid(row=0, column=4, padx=5)

    def refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        for i, (name, _) in enumerate(self.entries):
            self.tree.insert("", "end", iid=str(i), values=(name,))

    def selected_index(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return int(sel[0])

    def add_entry(self):
        dialog = AddEntryDialog(self, title="Add Entry")
        if not dialog.result:
            return
        name, pwd = dialog.result
        if not name or not pwd:
            messagebox.showerror("Error", "Name and password cannot be empty.")
            return
        token = self.fer.encrypt(pwd.encode()).decode("utf-8")
        self.entries.append((name, token))
        save_entries(self.entries)
        self.refresh_list()

    def view_entry(self):
        idx = self.selected_index()
        if idx is None:
            messagebox.showinfo("Info", "Select an entry first.")
            return
        name, token_text = self.entries[idx]
        try:
            decrypted = self.fer.decrypt(token_text.encode()).decode()
        except InvalidToken:
            messagebox.showerror("Error", "Could not decrypt entry (corrupted data).")
            return
        messagebox.showinfo(name, f"Password: {decrypted}")

    def copy_entry(self):
        idx = self.selected_index()
        if idx is None:
            messagebox.showinfo("Info", "Select an entry first.")
            return
        name, token_text = self.entries[idx]
        try:
            decrypted = self.fer.decrypt(token_text.encode()).decode()
        except InvalidToken:
            messagebox.showerror("Error", "Could not decrypt entry (corrupted data).")
            return
        self.clipboard_clear()
        self.clipboard_append(decrypted)
        messagebox.showinfo("Copied", f"Password for '{name}' copied to clipboard.")

    def delete_entry(self):
        idx = self.selected_index()
        if idx is None:
            messagebox.showinfo("Info", "Select an entry first.")
            return
        name, _ = self.entries[idx]
        if messagebox.askyesno("Confirm", f"Delete entry '{name}'?"):
            del self.entries[idx]
            save_entries(self.entries)
            self.refresh_list()

    def clear_all(self):
        if messagebox.askyesno("Confirm", "Delete ALL saved entries? This cannot be undone."):
            self.entries = []
            save_entries(self.entries)
            self.refresh_list()


def main():
    root = tk.Tk()
    root.withdraw()

    dialog = LoginDialog(root, title="Master Password")
    master_pwd = dialog.result
    if not master_pwd:
        root.destroy()
        return

    salt = get_or_create_salt()
    fernet_key = derive_key(master_pwd, salt)
    fer = Fernet(fernet_key)

    if not verify_master_password(fer):
        messagebox.showerror("Error", "Wrong master password.")
        root.destroy()
        return

    root.destroy()
    app = PasswordManagerApp(fer)
    app.mainloop()


if __name__ == "__main__":
    main()
