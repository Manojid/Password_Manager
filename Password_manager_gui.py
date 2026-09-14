import base64
import os
import secrets
import string

import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox, Querybox

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_FILE = "key.key"
CHECK_FILE = "check.key"
PASSWORD_FILE = "passwords.txt"

THEME = "darkly"


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


def password_strength(pwd: str):
    if not pwd:
        return "", "secondary"
    score = 0
    score += len(pwd) >= 8
    score += len(pwd) >= 12
    score += any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
    score += any(c.isdigit() for c in pwd)
    score += any(c in string.punctuation for c in pwd)
    if score <= 1:
        return "Weak", "danger"
    if score <= 3:
        return "Okay", "warning"
    return "Strong", "success"


def add_password_field(parent, label_text, bottom_pad=12):
    tb.Label(parent, text=label_text, bootstyle="secondary").pack(anchor="w")
    row = tb.Frame(parent)
    row.pack(fill=X, pady=(2, bottom_pad))
    entry = tb.Entry(row, show="*", font=("Segoe UI", 10))
    entry.pack(side=LEFT, fill=X, expand=True, ipady=3)
    show_var = tb.BooleanVar()
    tb.Checkbutton(
        row, text="👁", bootstyle="secondary-outline-toolbutton", width=3,
        variable=show_var, command=lambda: entry.config(show="" if show_var.get() else "*")
    ).pack(side=LEFT, padx=(5, 0))
    return entry


class LoginWindow(tb.Window):
    def __init__(self):
        super().__init__(themename=THEME)
        self.title("Password Manager — Unlock")
        self.geometry("400x520")
        self.resizable(False, False)
        self.fer = None

        card = tb.Frame(self, padding=30)
        card.pack(fill=BOTH, expand=True)

        tb.Label(card, text="🔐", font=("Segoe UI Emoji", 36), bootstyle="info").pack(pady=(0, 5))
        tb.Label(card, text="Secure Vault", font=("Segoe UI", 18, "bold")).pack()
        tb.Label(
            card, text="Enter your master password to continue",
            bootstyle="secondary", font=("Segoe UI", 9)
        ).pack(pady=(0, 15))

        self.pwd_var = tb.StringVar()
        entry = tb.Entry(card, textvariable=self.pwd_var, show="*", font=("Segoe UI", 11), width=28)
        entry.pack(pady=(0, 15), ipady=4)
        entry.bind("<Return>", lambda e: self.unlock())
        entry.focus_set()

        tb.Button(card, text="Unlock", bootstyle="info", command=self.unlock, width=20).pack(ipady=4)

        self.status = tb.Label(card, text="", bootstyle="danger", wraplength=320)
        self.status.pack(pady=(10, 0))

        tb.Button(
            card, text="Forgot master password?", bootstyle="link", command=self.forgot_password
        ).pack(pady=(15, 0))

    def unlock(self):
        master_pwd = self.pwd_var.get()
        if not master_pwd:
            self.status.config(text="Master password cannot be empty.")
            return

        salt = get_or_create_salt()
        fernet_key = derive_key(master_pwd, salt)
        fer = Fernet(fernet_key)

        if not verify_master_password(fer):
            self.status.config(text="Wrong master password.")
            self.pwd_var.set("")
            return

        self.fer = fer
        self.destroy()

    def forgot_password(self):
        confirmed = Messagebox.yesno(
            "If you forgot your master password, there is no way to recover it "
            "or the data encrypted with it. Resetting will PERMANENTLY ERASE all "
            "saved entries and let you set a brand new master password.\n\n"
            "Continue and erase everything?",
            "Reset Vault",
            parent=self,
        )
        if confirmed != "Yes":
            return

        for f in (SALT_FILE, CHECK_FILE, PASSWORD_FILE):
            if os.path.exists(f):
                os.remove(f)

        dialog = ResetVaultDialog(self)
        self.wait_window(dialog)
        if not dialog.result:
            return
        new_pwd, confirm_pwd = dialog.result

        if not new_pwd:
            self.status.config(text="New master password cannot be empty.")
            return
        if new_pwd != confirm_pwd:
            self.status.config(text="New passwords did not match. Try again.")
            return

        salt = get_or_create_salt()
        fer = Fernet(derive_key(new_pwd, salt))
        verify_master_password(fer)
        self.fer = fer
        self.status.config(text="")
        self.destroy()


class ResetVaultDialog(tb.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Set New Master Password")
        self.geometry("400x360")
        self.resizable(False, False)
        self.result = None
        self.transient(parent)
        self.grab_set()

        frm = tb.Frame(self, padding=20)
        frm.pack(fill=BOTH, expand=True)

        btn_row = tb.Frame(frm)
        btn_row.pack(fill=X, side=BOTTOM, pady=(15, 0))
        tb.Button(btn_row, text="Cancel", bootstyle="secondary", command=self.destroy).pack(side=RIGHT, padx=(5, 0))
        tb.Button(btn_row, text="Reset & Continue", bootstyle="danger", command=self.save).pack(side=RIGHT)

        tb.Label(
            frm, text="Your old vault has been erased. Set a new master password.",
            bootstyle="secondary", wraplength=360
        ).pack(anchor="w", pady=(0, 12))

        self.new_entry = add_password_field(frm, "New master password")
        self.confirm_entry = add_password_field(frm, "Confirm new master password", bottom_pad=8)

        self.new_entry.focus_set()

    def save(self):
        self.result = (self.new_entry.get(), self.confirm_entry.get())
        self.destroy()


class AddEntryDialog(tb.Toplevel):
    def __init__(self, parent, title="Add Entry", initial_name="", initial_pwd=""):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x440")
        self.resizable(False, False)
        self.result = None
        self.transient(parent)
        self.grab_set()

        frm = tb.Frame(self, padding=20)
        frm.pack(fill=BOTH, expand=True)

        # Pack the button row first so Tk reserves its space before the
        # fields above it — guarantees it's never pushed outside the window.
        btn_row = tb.Frame(frm)
        btn_row.pack(fill=X, side=BOTTOM, pady=(15, 0))
        tb.Button(btn_row, text="Cancel", bootstyle="secondary", command=self.cancel).pack(side=RIGHT, padx=(5, 0))
        tb.Button(btn_row, text="Save", bootstyle="success", command=self.save).pack(side=RIGHT)

        tb.Label(frm, text="Username / Website", bootstyle="secondary").pack(anchor="w")
        self.name_entry = tb.Entry(frm, font=("Segoe UI", 10))
        self.name_entry.insert(0, initial_name)
        self.name_entry.pack(fill=X, pady=(2, 12), ipady=3)

        tb.Label(frm, text="Password", bootstyle="secondary").pack(anchor="w")
        pwd_row = tb.Frame(frm)
        pwd_row.pack(fill=X, pady=(2, 4))
        self.pwd_entry = tb.Entry(pwd_row, show="*", font=("Segoe UI", 10))
        self.pwd_entry.insert(0, initial_pwd)
        self.pwd_entry.pack(side=LEFT, fill=X, expand=True, ipady=3)
        self.pwd_entry.bind("<KeyRelease>", lambda e: self.update_strength())
        self.show_var = tb.BooleanVar()
        tb.Checkbutton(
            pwd_row, text="👁", bootstyle="secondary-outline-toolbutton",
            variable=self.show_var, command=self.toggle_show, width=3
        ).pack(side=LEFT, padx=(5, 0))

        self.strength_label = tb.Label(frm, text="", font=("Segoe UI", 8, "bold"))
        self.strength_label.pack(anchor="w", pady=(0, 10))

        gen_row = tb.Frame(frm)
        gen_row.pack(fill=X, pady=(0, 15))
        tb.Label(gen_row, text="Generate length:").pack(side=LEFT)
        self.length_entry = tb.Entry(gen_row, width=5)
        self.length_entry.insert(0, "16")
        self.length_entry.pack(side=LEFT, padx=8)
        tb.Button(gen_row, text="Generate", bootstyle="info-outline", command=self.generate).pack(side=LEFT)

        self.name_entry.focus_set()
        self.update_strength()

    def toggle_show(self):
        self.pwd_entry.config(show="" if self.show_var.get() else "*")

    def update_strength(self):
        label, style = password_strength(self.pwd_entry.get())
        self.strength_label.config(text=label, bootstyle=style)

    def generate(self):
        try:
            length = int(self.length_entry.get())
        except ValueError:
            Messagebox.show_error("Length must be a number.", "Error", parent=self)
            return
        pwd = gen_password(length)
        self.pwd_entry.delete(0, "end")
        self.pwd_entry.insert(0, pwd)
        self.show_var.set(True)
        self.toggle_show()
        self.update_strength()

    def save(self):
        name = self.name_entry.get().strip()
        pwd = self.pwd_entry.get()
        if not name or not pwd:
            Messagebox.show_error("Name and password cannot be empty.", "Error", parent=self)
            return
        self.result = (name, pwd)
        self.destroy()

    def cancel(self):
        self.destroy()


class ChangePasswordDialog(tb.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Change Master Password")
        self.geometry("420x460")
        self.resizable(False, False)
        self.result = None
        self.transient(parent)
        self.grab_set()

        frm = tb.Frame(self, padding=20)
        frm.pack(fill=BOTH, expand=True)

        # Pack the button row first so Tk reserves its space before the
        # fields above it — guarantees it's never pushed outside the window.
        btn_row = tb.Frame(frm)
        btn_row.pack(fill=X, side=BOTTOM, pady=(15, 0))
        tb.Button(btn_row, text="Cancel", bootstyle="secondary", command=self.destroy).pack(side=RIGHT, padx=(5, 0))
        tb.Button(btn_row, text="Change Password", bootstyle="warning", command=self.save).pack(side=RIGHT)

        self.current_entry = add_password_field(frm, "Current master password")
        self.new_entry = add_password_field(frm, "New master password")
        self.confirm_entry = add_password_field(frm, "Confirm new master password", bottom_pad=8)

        self.error_label = tb.Label(frm, text="", bootstyle="danger", wraplength=380)
        self.error_label.pack(anchor="w", pady=(0, 10))

        self.current_entry.focus_set()

    def save(self):
        self.result = (
            self.current_entry.get(),
            self.new_entry.get(),
            self.confirm_entry.get(),
        )
        self.destroy()


class PasswordManagerApp(tb.Window):
    def __init__(self, fer: Fernet):
        super().__init__(themename=THEME)
        self.fer = fer
        self.title("Password Manager")
        self.geometry("880x560")
        self.minsize(820, 520)

        self.entries = load_entries()
        self.logout_requested = False

        header = tb.Frame(self, padding=(20, 15))
        header.pack(fill=X)
        tb.Label(header, text="🔐 Secure Vault", font=("Segoe UI", 16, "bold")).pack(side=LEFT)
        tb.Button(
            header, text="🚪 Logout", bootstyle="link", command=self.logout
        ).pack(side=RIGHT, padx=(0, 5))
        tb.Button(
            header, text="⚙ Change Master Password", bootstyle="link", command=self.change_master_password
        ).pack(side=RIGHT, padx=(0, 15))
        self.count_label = tb.Label(header, text="", bootstyle="secondary")
        self.count_label.pack(side=RIGHT)

        search_frame = tb.Frame(self, padding=(20, 0))
        search_frame.pack(fill=X, pady=(0, 10))
        self.search_var = tb.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh_list())
        search_entry = tb.Entry(search_frame, textvariable=self.search_var, font=("Segoe UI", 10))
        search_entry.pack(fill=X, ipady=4)
        search_entry.insert(0, "")
        self._add_placeholder(search_entry, "Search entries...")

        # Pack the fixed-height bottom bars BEFORE the expanding table so Tk
        # reserves their space first; the table then only claims what's left,
        # instead of greedily eating the whole cavity and pushing them off-window.
        self.status_bar = tb.Label(self, text="Ready", bootstyle="secondary", padding=(20, 5), anchor="w")
        self.status_bar.pack(fill=X, side=BOTTOM)

        btn_frame = tb.Frame(self, padding=(20, 12))
        btn_frame.pack(fill=X, side=BOTTOM)

        tb.Button(btn_frame, text="➕ Add", bootstyle="success", width=9, command=self.add_entry).pack(side=LEFT, padx=(0, 6))
        tb.Button(btn_frame, text="✏ Edit", bootstyle="warning-outline", width=9, command=self.edit_entry).pack(side=LEFT, padx=6)
        tb.Button(btn_frame, text="👁 View", bootstyle="info", width=9, command=self.view_entry).pack(side=LEFT, padx=6)
        tb.Button(btn_frame, text="📋 Copy", bootstyle="primary", width=9, command=self.copy_entry).pack(side=LEFT, padx=6)
        tb.Button(btn_frame, text="🗑 Delete", bootstyle="danger-outline", width=9, command=self.delete_entry).pack(side=LEFT, padx=6)
        tb.Button(btn_frame, text="Clear All", bootstyle="secondary-outline", width=9, command=self.clear_all).pack(side=RIGHT)

        table_frame = tb.Frame(self, padding=(20, 0))
        table_frame.pack(fill=BOTH, expand=True)

        self.tree = tb.Treeview(
            table_frame, columns=("name",), show="headings",
            selectmode="browse", bootstyle="dark", height=6
        )
        self.tree.heading("name", text="Username / Website")
        self.tree.column("name", anchor="w")
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        self.tree.bind("<Double-1>", lambda e: self.view_entry())

        scrollbar = tb.Scrollbar(table_frame, orient="vertical", command=self.tree.yview, bootstyle="round")
        scrollbar.pack(side=RIGHT, fill=Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.refresh_list()

    def _add_placeholder(self, entry, text):
        entry.insert(0, text)
        entry.config(foreground="gray")

        def on_focus_in(e):
            if entry.get() == text:
                entry.delete(0, "end")
                entry.config(foreground="white")

        def on_focus_out(e):
            if not entry.get():
                entry.insert(0, text)
                entry.config(foreground="gray")

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
        self._placeholder_text = text

    def refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().strip().lower()
        if query == getattr(self, "_placeholder_text", "").lower():
            query = ""
        shown = 0
        for i, (name, _) in enumerate(self.entries):
            if query and query not in name.lower():
                continue
            self.tree.insert("", "end", iid=str(i), values=(name,))
            shown += 1
        self.count_label.config(text=f"{shown} / {len(self.entries)} entries")

    def selected_index(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return int(sel[0])

    def set_status(self, text):
        self.status_bar.config(text=text)

    def add_entry(self):
        dialog = AddEntryDialog(self)
        self.wait_window(dialog)
        if not dialog.result:
            return
        name, pwd = dialog.result
        token = self.fer.encrypt(pwd.encode()).decode("utf-8")
        self.entries.append((name, token))
        save_entries(self.entries)
        self.refresh_list()
        self.set_status(f"Added entry: {name}")

    def edit_entry(self):
        idx = self.selected_index()
        if idx is None:
            Messagebox.show_info("Select an entry first.", "Info", parent=self)
            return
        name, token_text = self.entries[idx]
        try:
            decrypted = self.fer.decrypt(token_text.encode()).decode()
        except InvalidToken:
            Messagebox.show_error("Could not decrypt entry (corrupted data).", "Error", parent=self)
            return

        dialog = AddEntryDialog(self, title="Edit Entry", initial_name=name, initial_pwd=decrypted)
        self.wait_window(dialog)
        if not dialog.result:
            return
        new_name, new_pwd = dialog.result
        token = self.fer.encrypt(new_pwd.encode()).decode("utf-8")
        self.entries[idx] = (new_name, token)
        save_entries(self.entries)
        self.refresh_list()
        self.set_status(f"Updated entry: {new_name}")

    def logout(self):
        if Messagebox.yesno("Log out and lock the vault?", "Confirm", parent=self) == "Yes":
            self.logout_requested = True
            self.destroy()

    def view_entry(self):
        idx = self.selected_index()
        if idx is None:
            Messagebox.show_info("Select an entry first.", "Info", parent=self)
            return
        name, token_text = self.entries[idx]
        try:
            decrypted = self.fer.decrypt(token_text.encode()).decode()
        except InvalidToken:
            Messagebox.show_error("Could not decrypt entry (corrupted data).", "Error", parent=self)
            return
        Messagebox.show_info(f"Password: {decrypted}", name, parent=self)

    def copy_entry(self):
        idx = self.selected_index()
        if idx is None:
            Messagebox.show_info("Select an entry first.", "Info", parent=self)
            return
        name, token_text = self.entries[idx]
        try:
            decrypted = self.fer.decrypt(token_text.encode()).decode()
        except InvalidToken:
            Messagebox.show_error("Could not decrypt entry (corrupted data).", "Error", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(decrypted)
        self.set_status(f"Copied password for '{name}' to clipboard.")

    def delete_entry(self):
        idx = self.selected_index()
        if idx is None:
            Messagebox.show_info("Select an entry first.", "Info", parent=self)
            return
        name, _ = self.entries[idx]
        if Messagebox.yesno(f"Delete entry '{name}'?", "Confirm", parent=self) == "Yes":
            del self.entries[idx]
            save_entries(self.entries)
            self.refresh_list()
            self.set_status(f"Deleted entry: {name}")

    def change_master_password(self):
        dialog = ChangePasswordDialog(self)
        self.wait_window(dialog)
        if not dialog.result:
            return
        current_pwd, new_pwd, confirm_pwd = dialog.result

        if not new_pwd:
            Messagebox.show_error("New password cannot be empty.", "Error", parent=self)
            return
        if new_pwd != confirm_pwd:
            Messagebox.show_error("New passwords do not match.", "Error", parent=self)
            return

        salt = get_or_create_salt()
        current_fer = Fernet(derive_key(current_pwd, salt))
        if not verify_master_password(current_fer):
            Messagebox.show_error("Current master password is incorrect.", "Error", parent=self)
            return

        decrypted_entries = []
        for name, token_text in self.entries:
            try:
                decrypted_entries.append((name, current_fer.decrypt(token_text.encode()).decode()))
            except InvalidToken:
                Messagebox.show_error(
                    "Could not decrypt an existing entry. Aborting — nothing was changed.",
                    "Error", parent=self
                )
                return

        new_salt = os.urandom(16)
        new_fer = Fernet(derive_key(new_pwd, new_salt))

        with open(SALT_FILE, "wb") as f:
            f.write(new_salt)
        with open(CHECK_FILE, "wb") as f:
            f.write(new_fer.encrypt(b"check"))

        self.entries = [(name, new_fer.encrypt(pwd.encode()).decode("utf-8")) for name, pwd in decrypted_entries]
        save_entries(self.entries)

        self.fer = new_fer
        self.refresh_list()
        self.set_status("Master password changed successfully.")

    def clear_all(self):
        if Messagebox.yesno("Delete ALL saved entries? This cannot be undone.", "Confirm", parent=self) == "Yes":
            self.entries = []
            save_entries(self.entries)
            self.refresh_list()
            self.set_status("All entries cleared.")


def main():
    while True:
        login = LoginWindow()
        login.mainloop()

        if login.fer is None:
            return

        app = PasswordManagerApp(login.fer)
        app.mainloop()

        if not app.logout_requested:
            return


if __name__ == "__main__":
    main()
