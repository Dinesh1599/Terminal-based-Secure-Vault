from auth import signup, login
from database import init_db, add_vault_entry, get_vault_entries
from crypto_utils import key_derive, encrypt_data, decrypt_data
import time
import getpass

#INACTIVITY TIMER
INACTIVITY_TIMEOUT = 120

def menu():
    print("""
    SECURE VAULT ENTRY
          1. Signup
          2. Login
          3. Exit        
    """)

def user_menu():
    print("""
    VAULT MENU
    ===========
    1. Add Entry
    2. View Entry
    3. Logout
""")
def auto_lock(LAT): #Auto-Lock Function
    now = time.time()
    return (now - LAT) > INACTIVITY_TIMEOUT

def relogin(username):
    print("\n[*] Session Timeout - Inactivity")
    for attempt in range(3):
        password = getpass.getpass("Re enter User Password:")
        user = login(user, password)
        if user:
            salt = user['salt']
            encryption_key = key_derive(password, salt)
            print("[+] Vault Unlocked")     
            return encryption_key
        else:
            print('[-] Incorrect Password, Try Again.')
    print('[-] Too many failed attempts. Exiting Vault')
    exit(1)

def main():
    init_db()

    while True:
        menu()
        choice = input("Choice: ").strip()

        if choice == "1":
            username = input("Username:")
            while True:
                password = getpass.getpass("New Password: ")
                confirm_password = getpass.getpass("Confirm Password: ")

                if password != confirm_password:
                    print("[-] Passwords do not match. Please try again.")
                elif len(password) < 6:
                    print("[-] Password should be at least 6 characters long.")
                else:
                    break
            signup(username, password)
        
        elif choice == '2':
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            user = login(username, password)
            if user:
                salt = user['salt']
                encryption_key = key_derive(password, salt)
                last_activity = time.time()

                while True:
                    if auto_lock(last_activity):
                        encryption_key = relogin(username)
                        last_activity = time.time()
                    user_menu()
                    action = input("Action: ").strip()

                    if action == '1':
                        title = input("Entry Title: ")
                        secret = input("Secret Data: ")
                        encrypted = encrypt_data(encryption_key, secret)
                        add_vault_entry(user['id'], title, encrypted)
                        print("[+] Entry added.")
                        last_activity = time.time()

                    elif action == '2':
                        entries = get_vault_entries(user['id'])
                        if not entries:
                            print("[-] No Entries for User")
                        for entry in entries:
                            decrypted = decrypt_data(encryption_key, entry['encrypted_data'])
                            print(f"---\nTitle: {entry['title']}\nData: {decrypted}\n---")
                        last_activity = time.time()

                    elif action == '3':
                        print("[*] Logged out.")
                        break

                    else:
                        print("[-] Invalid choice.")
        elif choice == '3':
            print("[*] Exiting Vault. Goodbye.")
            break
        else:
            print("[-] Invalid choice.")

if __name__ == "__main__":
    main()
                        



