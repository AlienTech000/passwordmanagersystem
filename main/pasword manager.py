import os
import json
import hashlib
import base64
import random
import string
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, Scrollbar, Listbox

class PasswordManager:
    def __init__(self):
        self.password_file = "passwords.json"
        self.master_password_file = "master_password.hash"
        self.passwords = {}
        self.login_attempts = 0
        self.max_attempts = 3
        self.lockout_time = 300  # 5 minutes
        self.timeout = 300  # Auto-logout after 5 minutes
        self.last_activity = time.time()

        # Verify or set master password
        self.verify_master_password()

        # Load existing passwords
        self.load_passwords()

    def verify_master_password(self):
        """Verify or set the master password with a salt."""
        if os.path.exists(self.master_password_file):
            with open(self.master_password_file, "r") as file:
                stored_data = json.load(file)
                stored_master_password_hash = stored_data["hash"]
                salt = stored_data["salt"]

            while self.login_attempts < self.max_attempts:
                entered_password = simpledialog.askstring("Master Password", "🔑 Enter master password:", show='*')
                salted_password = (entered_password + salt).encode()
                entered_password_hash = hashlib.sha256(salted_password).hexdigest()

                if entered_password_hash == stored_master_password_hash:
                    messagebox.showinfo("Access Granted", "🚀 Welcome to the Password Manager!")
                    return
                else:
                    self.login_attempts += 1
                    messagebox.showerror("Error", f"❌ Invalid password. Attempt {self.login_attempts}/{self.max_attempts}")

            messagebox.showerror("Too Many Attempts", f"⏳ Too many attempts. Please wait {self.lockout_time // 60} minutes.")
            time.sleep(self.lockout_time)
            exit()
        else:
            new_password = simpledialog.askstring("Set Master Password", "🛠️ Set a new master password:", show='*')
            salt = self.generate_salt()
            salted_password = (new_password + salt).encode()
            password_hash = hashlib.sha256(salted_password).hexdigest()

            with open(self.master_password_file, "w") as file:
                json.dump({"hash": password_hash, "salt": salt}, file)

            messagebox.showinfo("Password Set", "💡 Master password set successfully.")

    def generate_salt(self, length=16):
        """Generates a random salt for hashing the master password."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def load_passwords(self):
        """Loads and decodes passwords from JSON file."""
        if os.path.exists(self.password_file):
            with open(self.password_file, "r") as file:
                encoded_data = json.load(file)
            for account, encoded_password in encoded_data.items():
                self.passwords[account] = base64.b64decode(encoded_password).decode()

    def save_passwords(self):
        """Encodes and saves passwords to JSON file."""
        encoded_data = {account: base64.b64encode(password.encode()).decode() for account, password in self.passwords.items()}
        with open(self.password_file, "w") as file:
            json.dump(encoded_data, file)

    def check_password_strength(self, password):
        """Checks the strength of the password."""
        if (len(password) >= 8 and any(c.isdigit() for c in password) and
                any(c.islower() for c in password) and any(c.isupper() for c in password) and
                any(c in string.punctuation for c in password)):
            return True
        return False

    def add_password(self, account, password):
        """Adds a new password with strength checking."""
        if self.check_password_strength(password):
            self.passwords[account] = password
            self.save_passwords()
            messagebox.showinfo("Success", f"✅ Password for {account} added successfully.")
        else:
            messagebox.showerror("Error", "❌ Failed to add password. It did not meet strength requirements.")

    def get_password(self, account):
        """Retrieves the password for an account."""
        password = self.passwords.get(account)
        if password:
            messagebox.showinfo("Password Retrieved", f"🔓 Password for {account} is: {password}")
        else:
            messagebox.showerror("Error", f"❌ No password found for {account}.")

    def delete_password(self, account):
        """Deletes the password for an account."""
        if account in self.passwords:
            del self.passwords[account]
            self.save_passwords()
            messagebox.showinfo("Success", f"🗑️ Password for {account} deleted successfully.")
        else:
            messagebox.showerror("Error", f"❌ No password found for {account}.")

    def generate_password(self, length=12):
        """Generates a secure password."""
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def backup_passwords(self):
        """Creates a backup of passwords."""
        self.save_passwords()
        if os.path.exists(self.password_file):
            with open(self.password_file, "r") as f, open("passwords_backup.json", "w") as backup:
                backup.write(f.read())
            messagebox.showinfo("Backup", "🛡️ Backup created successfully.")

    def restore_passwords(self):
        """Restores passwords from backup."""
        if os.path.exists("passwords_backup.json"):
            with open("passwords_backup.json", "r") as file:
                backup_data = json.load(file)
            self.passwords = {account: base64.b64decode(pw.encode()).decode() for account, pw in backup_data.items()}
            self.save_passwords()
            messagebox.showinfo("Restore", "📦 Backup restored successfully.")
        else:
            messagebox.showerror("Error", "❌ No backup found to restore.")

class PasswordManagerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Password Manager")
        self.manager = PasswordManager()

        # Create UI Elements
        self.create_widgets()

    def create_widgets(self):
        """Sets up the GUI components."""
        # Instructions Label
        self.instructions = tk.Label(self.root, text="🔐 Manage Your Passwords Easily", font=("Arial", 14))
        self.instructions.pack(pady=10)

        # Add Password Frame
        self.frame_add = tk.Frame(self.root)
        self.frame_add.pack(pady=10)

        self.label_account = tk.Label(self.frame_add, text="Account Name:")
        self.label_account.grid(row=0, column=0)
        self.entry_account = tk.Entry(self.frame_add, width=30)
        self.entry_account.grid(row=0, column=1)

        self.label_password = tk.Label(self.frame_add, text="Password:")
        self.label_password.grid(row=0, column=2)
        self.entry_password = tk.Entry(self.frame_add, width=30)
        self.entry_password.grid(row=0, column=3)

        self.button_add = tk.Button(self.frame_add, text="Add Password", command=self.add_password)
        self.button_add.grid(row=0, column=4)

        # Password List Frame
        self.frame_list = tk.Frame(self.root)
        self.frame_list.pack(pady=10)

        self.listbox = Listbox(self.frame_list, width=50, height=10)
        self.listbox.pack(side=tk.LEFT)

        self.scrollbar = Scrollbar(self.frame_list)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.listbox.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.listbox.yview)

        # Retrieve and Delete Buttons
        self.frame_buttons = tk.Frame(self.root)
        self.frame_buttons.pack(pady=10)

        self.button_retrieve = tk.Button(self.frame_buttons, text="Retrieve Password", command=self.retrieve_password)
        self.button_retrieve.pack(side=tk.LEFT, padx=5)

        self.button_delete = tk.Button(self.frame_buttons, text="Delete Password", command=self.delete_password)
        self.button_delete.pack(side=tk.LEFT, padx=5)

        # Generate Password Frame
        self.frame_generate = tk.Frame(self.root)
        self.frame_generate.pack(pady=10)

        self.button_generate = tk.Button(self.frame_generate, text="Generate Random Password", command=self.generate_password)
        self.button_generate.pack()

        # Backup/Restore Frame
        self.frame_backup = tk.Frame(self.root)
        self.frame_backup.pack(pady=10)

        self.button_backup = tk.Button(self.frame_backup, text="Backup", command=self.manager.backup_passwords)
        self.button_backup.pack(side=tk.LEFT, padx=5)

        self.button_restore = tk.Button(self.frame_backup, text="Restore", command=self.manager.restore_passwords)
        self.button_restore.pack(side=tk.LEFT, padx=5)

        self.update_password_list()

    def add_password(self):
        """Add password to the manager and update the listbox."""
        account = self.entry_account.get()
        password = self.entry_password.get()
        if not password:
            password = self.manager.generate_password()
            self.entry_password.delete(0, tk.END)
            self.entry_password.insert(0, password)
        self.manager.add_password(account, password)
        self.update_password_list()
        self.entry_account.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)

    def retrieve_password(self):
        """Retrieve password from the manager."""
        selected = self.listbox.curselection()
        if selected:
            account = self.listbox.get(selected[0])
            self.manager.get_password(account)
        else:
            messagebox.showwarning("Select Account", "⚠️ Please select an account to retrieve.")

    def delete_password(self):
        """Delete password from the manager and update the listbox."""
        selected = self.listbox.curselection()
        if selected:
            account = self.listbox.get(selected[0])
            self.manager.delete_password(account)
            self.update_password_list()
        else:
            messagebox.showwarning("Select Account", "⚠️ Please select an account to delete.")

    def generate_password(self):
        """Generate and display a password."""
        length = simpledialog.askinteger("Generate Password", "Enter password length (default 12):", minvalue=1)
        if length is None:
            length = 12
        password = self.manager.generate_password(length)
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, password)

    def update_password_list(self):
        """Updates the listbox with current passwords."""
        self.listbox.delete(0, tk.END)
        for account in self.manager.passwords:
            self.listbox.insert(tk.END, account)

def main():
    """Main function to run the Password Manager UI."""
    root = tk.Tk()
    PasswordManagerUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
