from cryptography.fernet import Fernet, InvalidToken
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import getpass
import secrets
import string
import os

def gen_password():
    length = int(input("How many charachter Password do you want to generate? : "))
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

def get_or_create_salt():
    salt_file = "key.key"
    if not os.path.exists(salt_file):
        salt = os.urandom(16)
        with open(salt_file, "wb") as f:
            f.write(salt)
        print("Salt file created.")
    else:
        with open(salt_file, "rb") as f:
            salt = f.read()
    return salt

master_pwd = getpass.getpass("Enter your master password: ")
salt = get_or_create_salt()
fernet_key = derive_key(master_pwd, salt)
fer = Fernet(fernet_key)

def Add():
    name = input("Enter username or website name: ").strip()
    if not name:
        print("Name cannot be empty.")
        return

    choice = input("Do you want to generate a password? (yes/no): ").lower()
    if choice == 'yes':
        pwd = gen_password()
        print(f"Generated password: {pwd}")
    else:
        pwd = getpass.getpass("Enter the password: ")

    token = fer.encrypt(pwd.encode())
    token_text = token.decode('utf-8')
    with open("passwords.txt", "a", encoding="utf-8") as f:
        f.write(name + "|" + token_text + "\n")
    print("Password added.")

def view():
    password_file = "passwords.txt"
    if not os.path.exists(password_file):
        print("No passwords stored yet.")
        return

    with open(password_file, "r", encoding="utf-8") as f:
        for line in f:
            data = line.strip()
            if not data:
                continue
            try:
                user, token_text = data.split("|", 1)
                decrypted = fer.decrypt(token_text.encode()).decode()
                print(f"User/Website: {user} | Password: {decrypted}")
            except InvalidToken:
                print("Error: Wrong master password or data corrupted.")
                return
            except ValueError:
                print("Error: Malformed data in file.")
                continue

def clear():
    password_file = "passwords.txt"
    if not os.path.exists(password_file):
        print("No data to clear.")
        return

    with open(password_file, "w", encoding="utf-8") as f:
        pass
    print("All data cleared!")

print("Welcome Password Manager")

while True:
    choice = input("Select option:\n1. View\n2. Add\n3. Clear all\n4. Quit\nEnter your choice: ").strip().lower()

    if choice == "1" or choice == "view":
        view()
    elif choice == "2" or choice == "add":
        Add()
    elif choice == "3" or choice == "clear all":
        while True:
            clr = input("Are you sure you want to clear all data? (yes/no): ").lower()
            if clr == "yes":
                clear()
                break
            elif clr == "no":
                break
            else:
                print("Invalid choice, enter yes/no")
    elif choice == "4" or choice == "quit":
        print("Goodbye!")
        break
    else:
        print("Invalid option. Please try again.")