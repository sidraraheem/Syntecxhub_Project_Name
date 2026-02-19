from cryptography.fernet import Fernet


class PasswordManager:

    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}

    def create_key(self, path):
        self.key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(self.key)

    def load_key(self, path):
        with open(path, 'rb') as f:
            self.key = f.read()

    def create_password_file(self, path, initial_values=None):
        self.password_file = path

        if initial_values is not None:
            for site, password in initial_values.items():
                self.add_password(site, password)

    def load_password_file(self, path):
        self.password_file = path

        with open(path, 'r') as f:
            for line in f:
                site, encrypted = line.strip().split(":")
                decrypted = Fernet(self.key).decrypt(encrypted.encode()).decode()
                self.password_dict[site] = decrypted

    def add_password(self, site, password):
        self.password_dict[site] = password

        if self.password_file is not None:
            with open(self.password_file, 'a') as f:
                encrypted = Fernet(self.key).encrypt(password.encode())
                f.write(site + ":" + encrypted.decode() + "\n")

    def get_password(self, site):
        return self.password_dict.get(site, "Password not found!")


def main():
    default_passwords = {
        "email": "12345678",
        "facebook": "myfbpassword",
        "youtube": "helloworld123",
        "instagram": "myinstapassword"
    }

    pm = PasswordManager()

    print("""
    What do you want to do?
    (1) Create a new key
    (2) Load an existing key
    (3) Create a new password file
    (4) Load an existing password file
    (5) Add a new password
    (6) Get a password
    (q) Quit
    """)

    while True:

        choice = input("Enter your choice: ")

        if choice == "1":
            path = input("Enter key file path: ")
            pm.create_key(path)

        elif choice == "2":
            path = input("Enter key file path: ")
            pm.load_key(path)

        elif choice == "3":
            path = input("Enter password file path: ")
            pm.create_password_file(path, default_passwords)

        elif choice == "4":
            path = input("Enter password file path: ")
            pm.load_password_file(path)

        elif choice == "5":
            site = input("Enter site: ")
            password = input("Enter password: ")
            pm.add_password(site, password)

        elif choice == "6":
            site = input("Enter site: ")
            print(f"Password for {site} is {pm.get_password(site)}")

        elif choice == "q":
            print("Bye")
            break

        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
