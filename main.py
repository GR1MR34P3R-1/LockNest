import os
import sqlite3
import random
import string
import tkinter as tk
import sys
from tkinter import messagebox, ttk
from datetime import datetime
import hashlib
import base64
from cryptography.fernet import Fernet

CLIPBOARD_CLEAR_DELAY_MINUTES = 0.5
INACTIVITY_LOCK_DELAY_MINUTES = 0.5

CLIPBOARD_CLEAR_DELAY = int(CLIPBOARD_CLEAR_DELAY_MINUTES * 60 * 1000)
INACTIVITY_LOCK_DELAY = int(INACTIVITY_LOCK_DELAY_MINUTES * 60 * 1000)

# Fixed window sizes to accommodate all content, including the longest passwords (up to 40 characters).
MAIN_WINDOW_SIZE = "555x325"
VIEW_INFO_SIZE = "980x435"
HISTORY_VIEW_SIZE = "1265x580"
DB_NAME = "keyvault.db"
DB_FOLDER = "SecureStore"

def get_db_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(current_dir, DB_FOLDER)
    os.makedirs(folder_path, exist_ok=True)
    return os.path.join(folder_path, DB_NAME)

def hash_password(password, salt):
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt + pwdhash).decode('utf-8')

def verify_password(stored_password, provided_password):
    decoded = base64.b64decode(stored_password)
    salt = decoded[:16]
    stored_pwdhash = decoded[16:]
    pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return stored_pwdhash == pwdhash

def generate_key(master_password):
    return base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest())

def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data.encode('utf-8')).decode('utf-8')

def decrypt_data(data, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(data.encode('utf-8')).decode('utf-8')

def generate_password(length=12, include_letters=True, include_digits=True, include_symbols=True):
    characters = ''
    if include_letters:
        characters += string.ascii_letters
    if include_digits:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError("At least one character type should be selected.")

    password = ''.join(random.choice(characters) for _ in range(length))
    
    if len(password) > 40:
        password = password[:40]

    return password

def get_local_timestamp():
    local_time = datetime.now().astimezone()
    formatted_time = local_time.strftime("%Y-%m-%d %I:%M:%S %p")
    return formatted_time

def format_phone_number(phone):
    digits = ''.join(filter(str.isdigit, phone))
    formatted_phone = '-'.join([digits[:3], digits[3:6], digits[6:10]]) if len(digits) > 6 else digits
    return formatted_phone

class DatabaseManager:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                                id INTEGER PRIMARY KEY,
                                service_name TEXT,
                                password TEXT,
                                email TEXT,
                                username TEXT,
                                phone TEXT,
                                salt TEXT,
                                timestamp TEXT)''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS password_history (
                                id INTEGER PRIMARY KEY,
                                record_id INTEGER,
                                service_name TEXT,
                                password TEXT,
                                email TEXT,
                                username TEXT,
                                phone TEXT,
                                salt TEXT,
                                timestamp TEXT,
                                FOREIGN KEY(record_id) REFERENCES passwords(id))''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS master_password (
                                id INTEGER PRIMARY KEY,
                                password_hash TEXT,
                                salt TEXT)''')
        self.conn.commit()

    def save_password(self, service_name, password, email, username, phone, key):
        timestamp = get_local_timestamp()
        salt = os.urandom(16)
        encrypted_password = encrypt_data(password, key)
        encrypted_email = encrypt_data(email, key) if email else ""
        encrypted_username = encrypt_data(username, key) if username else ""
        formatted_phone = format_phone_number(phone)
        encrypted_phone = encrypt_data(formatted_phone, key) if phone else ""
        salt_encoded = base64.b64encode(salt).decode('utf-8')
        self.cursor.execute("INSERT INTO passwords (service_name, password, email, username, phone, salt, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (service_name, encrypted_password, encrypted_email, encrypted_username, encrypted_phone, salt_encoded, timestamp))
        record_id = self.cursor.lastrowid
        self.cursor.execute("INSERT INTO password_history (record_id, service_name, password, email, username, phone, salt, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (record_id, service_name, encrypted_password, encrypted_email, encrypted_username, encrypted_phone, salt_encoded, timestamp))
        self.conn.commit()

    def get_saved_passwords(self, key):
        self.cursor.execute("SELECT * FROM passwords")
        records = self.cursor.fetchall()
        decrypted_records = []
        for record in records:
            record_id, service_name, encrypted_password, email, username, phone, salt, timestamp = record
            decrypted_password = decrypt_data(encrypted_password, key)
            decrypted_email = decrypt_data(email, key) if email else ""
            decrypted_username = decrypt_data(username, key) if username else ""
            decrypted_phone = decrypt_data(phone, key) if phone else ""
            decrypted_records.append((record_id, service_name, decrypted_password, decrypted_email, decrypted_username, decrypted_phone, salt, timestamp))
        return decrypted_records

    def get_password_history(self, key):
        self.cursor.execute("SELECT * FROM password_history ORDER BY timestamp DESC")
        records = self.cursor.fetchall()
        decrypted_records = []
        for record in records:
            history_id, record_id, service_name, encrypted_password, email, username, phone, salt, timestamp = record
            decrypted_password = decrypt_data(encrypted_password, key)
            decrypted_email = decrypt_data(email, key) if email else ""
            decrypted_username = decrypt_data(username, key) if username else ""
            decrypted_phone = decrypt_data(phone, key) if phone else ""
            decrypted_records.append((history_id, record_id, service_name, decrypted_password, decrypted_email, decrypted_username, decrypted_phone, salt, timestamp))
        return decrypted_records

    def update_record(self, record_id, service_name, password, email, username, phone, key):
        timestamp = get_local_timestamp()
        encrypted_password = encrypt_data(password, key)
        encrypted_email = encrypt_data(email, key) if email else ""
        encrypted_username = encrypt_data(username, key) if username else ""
        formatted_phone = format_phone_number(phone)
        encrypted_phone = encrypt_data(formatted_phone, key) if phone else ""
        self.cursor.execute("UPDATE passwords SET service_name = ?, password = ?, email = ?, username = ?, phone = ?, timestamp = ? WHERE id = ?",
                       (service_name, encrypted_password, encrypted_email, encrypted_username, encrypted_phone, timestamp, record_id))
        self.cursor.execute("INSERT INTO password_history (record_id, service_name, password, email, username, phone, salt, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (record_id, service_name, encrypted_password, encrypted_email, encrypted_username, encrypted_phone, base64.b64encode(os.urandom(16)).decode('utf-8'), timestamp))
        self.conn.commit()

    def update_master_password(self, new_master_password, master_password):
        self.cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
        result = self.cursor.fetchone()
        if result:
            stored_password, salt = result
            salt = base64.b64decode(salt)
            current_key = generate_key(master_password)
            
            records = self.get_saved_passwords(current_key)
            history_records = self.get_password_history(current_key)
            new_key = generate_key(new_master_password)
            
            for record in records:
                record_id, service_name, password, email, username, phone, salt, timestamp = record
                self.update_record(record_id, service_name, password, email, username, phone, new_key)
            
            for record in history_records:
                history_id, record_id, service_name, password, email, username, phone, salt, timestamp = record
                encrypted_password = encrypt_data(password, new_key)
                encrypted_email = encrypt_data(email, new_key) if email else ""
                encrypted_username = encrypt_data(username, new_key) if username else ""
                encrypted_phone = encrypt_data(phone, new_key) if phone else ""
                self.cursor.execute("UPDATE password_history SET service_name = ?, password = ?, email = ?, username = ?, phone = ?, salt = ?, timestamp = ? WHERE id = ?",
                               (service_name, encrypted_password, encrypted_email, encrypted_username, encrypted_phone, salt, timestamp, history_id))
            
            new_salt = os.urandom(16)
            password_hash = hash_password(new_master_password, new_salt)
            self.cursor.execute("UPDATE master_password SET password_hash = ?, salt = ? WHERE id = 1", 
                           (password_hash, base64.b64encode(new_salt).decode('utf-8')))
            self.conn.commit()

    def set_master_password(self, master_password):
        salt = os.urandom(16)
        password_hash = hash_password(master_password, salt)
        self.cursor.execute("INSERT INTO master_password (password_hash, salt) VALUES (?, ?)", 
                       (password_hash, base64.b64encode(salt).decode('utf-8')))
        self.conn.commit()
        return master_password

    def verify_master_password(self, master_password):
        self.cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
        result = self.cursor.fetchone()
        if result:
            stored_password, salt = result
            if verify_password(stored_password, master_password):
                return master_password
            else:
                messagebox.showerror("Error", "Invalid master password.")
                return None
        else:
            return self.set_master_password(master_password)

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LockNest")
        self.root.geometry(MAIN_WINDOW_SIZE)
        self.db_manager = DatabaseManager(get_db_path())
        self.current_page = 0
        self.history_page = 0
        self.current_key = None

        self.inactivity_timer = None
        self.clipboard_clear_timer = None

        self.is_first_time = self.check_first_time()

        self.create_widgets()
        self.setup_inactivity_timer()
        self.bind_shortcuts()
        self.bind_all_events()

        self.root.attributes('-topmost', True)  # Make the window stay on top

    def create_widgets(self):
        self.master_password_frame = tk.Frame(self.root)
        self.master_password_frame.pack(fill='both', expand=1)

        self.master_password_label = tk.Label(self.master_password_frame, text="Set Master Password:" if self.is_first_time else "Enter Master Password:")
        self.master_password_label.pack(pady=10)

        self.master_password_entry = tk.Entry(self.master_password_frame, show='*')
        self.master_password_entry.pack(pady=5)
        self.master_password_entry.bind('<Return>', self.authenticate_master_password)

        tk.Button(self.master_password_frame, text="Submit", command=self.authenticate_master_password).pack(pady=20)

        self.generate_password_frame = tk.Frame(self.root)
        self.view_passwords_frame = tk.Frame(self.root)
        self.view_history_frame = tk.Frame(self.root)

        self.frame_generate = ttk.Frame(self.generate_password_frame, padding="10 10 10 10")
        self.frame_generate.pack(expand=True, fill="both")

        tk.Label(self.frame_generate, text="Select the length of the password:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.length_slider = tk.Scale(self.frame_generate, from_=4, to=40, orient=tk.HORIZONTAL)
        self.length_slider.grid(row=0, column=1, pady=5, padx=5)

        tk.Label(self.frame_generate, text="Enter the name of the service or website (optional):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.service_entry = tk.Entry(self.frame_generate)
        self.service_entry.grid(row=1, column=1, pady=5, padx=5)

        tk.Label(self.frame_generate, text="Enter your email (optional):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.email_entry = tk.Entry(self.frame_generate)
        self.email_entry.grid(row=2, column=1, pady=5, padx=5)

        tk.Label(self.frame_generate, text="Enter your username (optional):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry = tk.Entry(self.frame_generate)
        self.username_entry.grid(row=3, column=1, pady=5, padx=5)

        tk.Label(self.frame_generate, text="Enter your phone number (optional):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.phone_entry = tk.Entry(self.frame_generate)
        self.phone_entry.grid(row=4, column=1, pady=5, padx=5)
        self.phone_entry.bind('<KeyRelease>', self.format_phone_entry)

        self.letters_var = tk.BooleanVar()
        self.digits_var = tk.BooleanVar()
        self.symbols_var = tk.BooleanVar()

        tk.Checkbutton(self.frame_generate, text="Include Letters", variable=self.letters_var).grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        tk.Checkbutton(self.frame_generate, text="Include Digits", variable=self.digits_var).grid(row=5, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Checkbutton(self.frame_generate, text="Include Symbols", variable=self.symbols_var).grid(row=6, column=0, sticky=tk.W, padx=5, pady=5)

        self.button_frame = tk.Frame(self.frame_generate)
        self.button_frame.grid(row=7, columnspan=2, pady=5)

        tk.Button(self.button_frame, text="Generate and Save Password", command=self.generate_and_save_password).pack(side=tk.LEFT, padx=5)
        tk.Button(self.button_frame, text="View Saved Info", command=self.show_view_passwords_frame).pack(side=tk.LEFT, padx=5)
        tk.Button(self.button_frame, text="View History", command=self.show_view_history_frame).pack(side=tk.LEFT, padx=5)
        tk.Button(self.button_frame, text="Update Master Password", command=self.open_update_master_password_window).pack(side=tk.LEFT, padx=5)

        self.result_label = tk.Label(self.frame_generate, text="")
        self.result_label.grid(row=8, columnspan=2, pady=5)

        self.view_passwords_frame.pack_forget()
        self.view_history_frame.pack_forget()

    def setup_inactivity_timer(self):
        self.reset_inactivity_timer()

    def reset_inactivity_timer(self, event=None):
        if self.master_password_frame.winfo_ismapped():
            return
        if self.inactivity_timer:
            self.root.after_cancel(self.inactivity_timer)
        self.inactivity_timer = self.root.after(INACTIVITY_LOCK_DELAY, self.lock_application)

    def lock_application(self):
        if self.master_password_frame.winfo_ismapped():
            return
        self.current_key = None
        self.master_password_entry.delete(0, tk.END)
        self.generate_password_frame.pack_forget()
        self.view_passwords_frame.pack_forget()
        self.view_history_frame.pack_forget()
        self.master_password_frame.pack(fill='both', expand=1)
        self.root.geometry(MAIN_WINDOW_SIZE)
        messagebox.showinfo("Locked", "The application has been locked due to inactivity. Please enter the master password to continue.")

    def authenticate_master_password(self, event=None):
        master_password = self.master_password_entry.get().strip()
        if not master_password:
            messagebox.showerror("Error", "Master password cannot be empty.")
            return

        if self.is_first_time:
            self.current_key = generate_key(self.db_manager.set_master_password(master_password))
            self.is_first_time = False
            self.master_password_label.config(text="Enter Master Password:")
            messagebox.showinfo("Success", "Master password set successfully!")
            self.master_password_entry.delete(0, tk.END)
            self.master_password_frame.pack_forget()
            self.show_generate_password_frame()
        else:
            master_password = self.db_manager.verify_master_password(master_password)
            if master_password:
                self.current_key = generate_key(master_password)
                self.master_password_entry.delete(0, tk.END)
                self.master_password_frame.pack_forget()
                self.show_generate_password_frame()
            else:
                self.root.destroy()

    def generate_and_save_password(self):
        self.reset_inactivity_timer()
        try:
            length = int(self.length_slider.get())

            service_name = self.service_entry.get().strip()
            email = self.email_entry.get().strip()
            username = self.username_entry.get().strip()
            phone = self.phone_entry.get().strip()

            include_letters = self.letters_var.get()
            include_digits = self.digits_var.get()
            include_symbols = self.symbols_var.get()

            password = generate_password(length, include_letters, include_digits, include_symbols)
            self.db_manager.save_password(service_name, password, email, username, phone, self.current_key)

            self.result_label.config(text=f"Generated Password: {password}")
            messagebox.showinfo("Success", "Password saved successfully!")

            # Clear the input fields after saving the password
            self.service_entry.delete(0, tk.END)
            self.email_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.phone_entry.delete(0, tk.END)
            self.length_slider.set(12)
            self.letters_var.set(True)
            self.digits_var.set(True)
            self.symbols_var.set(True)
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))


    def show_generate_password_frame(self):
        self.generate_password_frame.pack(fill='both', expand=1)
        self.view_passwords_frame.pack_forget()
        self.view_history_frame.pack_forget()
        self.root.geometry(MAIN_WINDOW_SIZE)

    def show_view_passwords_frame(self):
        self.view_saved_info()
        self.view_passwords_frame.pack(fill='both', expand=1)
        self.generate_password_frame.pack_forget()
        self.view_history_frame.pack_forget()
        self.root.geometry(VIEW_INFO_SIZE)

    def show_view_history_frame(self):
        self.view_history_info()
        self.view_history_frame.pack(fill='both', expand=1)
        self.generate_password_frame.pack_forget()
        self.view_passwords_frame.pack_forget()
        self.root.geometry(HISTORY_VIEW_SIZE)

    def view_saved_info(self):
        for widget in self.view_passwords_frame.winfo_children():
            widget.destroy()

        saved_passwords = self.db_manager.get_saved_passwords(self.current_key)

        if saved_passwords:
            start_index = self.current_page * 6
            end_index = start_index + 6
            for idx, record in enumerate(saved_passwords[start_index:end_index]):
                col = idx % 2
                row = (idx // 2) * 7

                record_id, service_name, password, email, username, phone, salt, timestamp = record

                tk.Label(self.view_passwords_frame, text=f"Service/Website: {service_name}", font=("Helvetica", 10, "bold")).grid(row=row, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_passwords_frame, text=f"Password: {password}", font=("Helvetica", 10)).grid(row=row+1, column=col*4, sticky=tk.W, padx=5, pady=2)

                tk.Label(self.view_passwords_frame, text=f"Email: {email if email else 'N/A'}", font=("Helvetica", 8)).grid(row=row+2, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_passwords_frame, text=f"Username: {username if username else 'N/A'}", font=("Helvetica", 8)).grid(row=row+3, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_passwords_frame, text=f"Phone: {phone if phone else 'N/A'}", font=("Helvetica", 8)).grid(row=row+4, column=col*4, sticky=tk.W, padx=5, pady=2)

                tk.Button(self.view_passwords_frame, text="Copy", command=lambda p=password: self.copy_to_clipboard(p)).grid(row=row+1, column=col*4+1, pady=2, padx=5, sticky=tk.W)
                tk.Button(self.view_passwords_frame, text="Modify", command=lambda idx=record_id: self.open_modify_window(idx)).grid(row=row+1, column=col*4+2, pady=2, padx=5, sticky=tk.W)

            self.view_passwords_frame.pack(fill='both', expand=1)
            self.view_passwords_frame.pack_propagate(False)
            navigation_frame = tk.Frame(self.view_passwords_frame)
            navigation_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)

            prev_button = tk.Button(navigation_frame, text="Prev", command=self.prev_page)
            prev_button.pack(side=tk.LEFT, padx=5)

            next_button = tk.Button(navigation_frame, text="Next", command=self.next_page)
            next_button.pack(side=tk.LEFT, padx=5)

            page_label = tk.Label(navigation_frame, text=f"Page {self.current_page + 1}")
            page_label.pack(side=tk.LEFT, padx=5)

            back_button = tk.Button(navigation_frame, text="Back to Main Page", command=self.show_generate_password_frame)
            back_button.pack(side=tk.LEFT, padx=5)

            self.root.geometry(VIEW_INFO_SIZE)
        else:
            tk.Label(self.view_passwords_frame, text="No saved passwords found.", font=("Helvetica", 12)).pack(padx=10, pady=5)
            back_button = tk.Button(self.view_passwords_frame, text="Back to Main Page", command=self.show_generate_password_frame)
            back_button.pack(pady=10)

    def view_history_info(self):
        for widget in self.view_history_frame.winfo_children():
            widget.destroy()

        history_records = self.db_manager.get_password_history(self.current_key)

        if history_records:
            start_index = self.history_page * 9
            end_index = start_index + 9
            for idx, record in enumerate(history_records[start_index:end_index]):
                col = idx % 3
                row = (idx // 3) * 8

                history_id, record_id, service_name, password, email, username, phone, salt, timestamp = record

                tk.Label(self.view_history_frame, text=f"Timestamp: {timestamp}", font=("Helvetica", 10, "bold")).grid(row=row, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_history_frame, text=f"Service/Website: {service_name}", font=("Helvetica", 10)).grid(row=row+1, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_history_frame, text=f"Password: {password}", font=("Helvetica", 10)).grid(row=row+2, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_history_frame, text=f"Email: {email if email else 'N/A'}", font=("Helvetica", 8)).grid(row=row+3, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_history_frame, text=f"Username: {username if username else 'N/A'}", font=("Helvetica", 8)).grid(row=row+4, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_history_frame, text=f"Phone: {phone if phone else 'N/A'}", font=("Helvetica", 8)).grid(row=row+5, column=col*4, sticky=tk.W, padx=5, pady=2)
                tk.Label(self.view_history_frame, text=f"----------------------------------", font=("Helvetica", 8)).grid(row=row+6, column=col*4, sticky=tk.W, padx=5, pady=2)

                tk.Button(self.view_history_frame, text="Copy", command=lambda p=password: self.copy_to_clipboard(p)).grid(row=row+2, column=col*4+1, pady=2, padx=5, sticky=tk.W)

            self.view_history_frame.pack(fill='both', expand=1)
            self.view_history_frame.pack_propagate(False)
            navigation_frame = tk.Frame(self.view_history_frame)
            navigation_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)

            prev_button = tk.Button(navigation_frame, text="Prev", command=self.prev_history_page)
            prev_button.pack(side=tk.LEFT, padx=5)

            next_button = tk.Button(navigation_frame, text="Next", command=self.next_history_page)
            next_button.pack(side=tk.LEFT, padx=5)

            page_label = tk.Label(navigation_frame, text=f"Page {self.history_page + 1}")
            page_label.pack(side=tk.LEFT, padx=5)

            back_button = tk.Button(navigation_frame, text="Back to Main Page", command=self.show_generate_password_frame)
            back_button.pack(side=tk.LEFT, padx=5)

            self.root.geometry(HISTORY_VIEW_SIZE)
        else:
            tk.Label(self.view_history_frame, text="No history records found.", font=("Helvetica", 12)).pack(padx=10, pady=5)
            back_button = tk.Button(self.view_history_frame, text="Back to Main Page", command=self.show_generate_password_frame)
            back_button.pack(pady=10)

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.view_saved_info()

    def next_page(self):
        saved_passwords = self.db_manager.get_saved_passwords(self.current_key)
        if self.current_page < (len(saved_passwords) - 1) // 6:
            self.current_page += 1
            self.view_saved_info()

    def prev_history_page(self):
        if self.history_page > 0:
            self.history_page -= 1
            self.view_history_info()

    def next_history_page(self):
        history_records = self.db_manager.get_password_history(self.current_key)
        if self.history_page < (len(history_records) - 1) // 9:
            self.history_page += 1
            self.view_history_info()

    def open_modify_window(self, record_id):
        modify_window = tk.Toplevel(self.root)
        modify_window.title("Modify Info")
        modify_window.attributes('-topmost', True)  # Make the modify window stay on top

        cursor = self.db_manager.cursor
        cursor.execute("SELECT * FROM passwords WHERE id = ?", (record_id,))
        service_name, encrypted_password, email, username, phone, salt, timestamp = cursor.fetchone()[1:]
        password = decrypt_data(encrypted_password, self.current_key)
        email = decrypt_data(email, self.current_key) if email else ""
        username = decrypt_data(username, self.current_key) if username else ""
        phone = decrypt_data(phone, self.current_key) if phone else ""

        tk.Label(modify_window, text="Service Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        service_entry = tk.Entry(modify_window)
        service_entry.grid(row=0, column=1, pady=5, padx=5)
        service_entry.insert(0, service_name)

        tk.Label(modify_window, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        password_entry = tk.Entry(modify_window)
        password_entry.grid(row=1, column=1, pady=5, padx=5)
        password_entry.insert(0, password)

        tk.Label(modify_window, text="Email:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        email_entry = tk.Entry(modify_window)
        email_entry.grid(row=2, column=1, pady=5, padx=5)
        email_entry.insert(0, email)

        tk.Label(modify_window, text="Username:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        username_entry = tk.Entry(modify_window)
        username_entry.grid(row=3, column=1, pady=5, padx=5)
        username_entry.insert(0, username)

        tk.Label(modify_window, text="Phone:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        phone_entry = tk.Entry(modify_window)
        phone_entry.grid(row=4, column=1, pady=5, padx=5)
        phone_entry.insert(0, phone)
        phone_entry.bind('<KeyRelease>', lambda event, e=phone_entry: self.format_phone_entry(event, e))

        def save_changes():
            new_service_name = service_entry.get().strip()
            new_password = password_entry.get().strip()
            new_email = email_entry.get().strip()
            new_username = username_entry.get().strip()
            new_phone = phone_entry.get().strip()

            self.db_manager.update_record(record_id, new_service_name, new_password, new_email, new_username, new_phone, self.current_key)
            messagebox.showinfo("Success", "Information updated successfully!")
            modify_window.destroy()
            self.view_saved_info()

        tk.Button(modify_window, text="Save Changes", command=save_changes).grid(row=5, columnspan=2, pady=10)

        modify_window.grab_set()  # Make the modify window modal
        self.root.wait_window(modify_window)  # Wait until the modify window is closed

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", "Copied to clipboard")
        self.reset_clipboard_clear_timer()

    def reset_clipboard_clear_timer(self):
        if self.clipboard_clear_timer:
            self.root.after_cancel(self.clipboard_clear_timer)
        self.clipboard_clear_timer = self.root.after(CLIPBOARD_CLEAR_DELAY, self.clear_clipboard)

    def clear_clipboard(self):
        self.root.clipboard_clear()
        self.root.update()
        messagebox.showinfo("Clipboard Cleared", "Clipboard data has been cleared for security.")

    def open_update_master_password_window(self):
        update_window = tk.Toplevel(self.root)
        update_window.title("Update Master Password")
        update_window.attributes('-topmost', True)  # Make the update window stay on top

        tk.Label(update_window, text="Current Master Password:").grid(row=0, column=0, padx=5, pady=5)
        current_password_entry = tk.Entry(update_window, show='*')
        current_password_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(update_window, text="New Master Password:").grid(row=1, column=0, padx=5, pady=5)
        new_password_entry = tk.Entry(update_window, show='*')
        new_password_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(update_window, text="Confirm New Master Password:").grid(row=2, column=0, padx=5, pady=5)
        confirm_password_entry = tk.Entry(update_window, show='*')
        confirm_password_entry.grid(row=2, column=1, padx=5, pady=5)

        def save_new_master_password():
            current_password = current_password_entry.get().strip()
            new_password = new_password_entry.get().strip()
            confirm_password = confirm_password_entry.get().strip()

            if not current_password or not new_password or not confirm_password:
                messagebox.showerror("Error", "All fields are required.")
                return

            cursor = self.db_manager.cursor
            cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
            result = cursor.fetchone()
            if result:
                stored_password, salt = result
                salt = base64.b64decode(salt)
                if verify_password(stored_password, current_password):
                    if new_password == confirm_password:
                        self.db_manager.update_master_password(new_password, current_password)
                        messagebox.showinfo("Success", "Master password updated successfully! The application will now close. Please restart the application.")
                        update_window.destroy()
                        self.root.destroy()  # Close the application
                    else:
                        messagebox.showerror("Error", "New passwords do not match.")
                else:
                    messagebox.showerror("Error", "Current master password is incorrect.")
            else:
                messagebox.showerror("Error", "Master password not set.")

        tk.Button(update_window, text="Update Password", command=save_new_master_password).grid(row=3, columnspan=2, pady=10)

        update_window.grab_set()  # Make the update window modal
        self.root.wait_window(update_window)  # Wait until the update window is closed

    def emergency_lockdown(self):
        self.current_key = None
        self.master_password_entry.delete(0, tk.END)
        self.generate_password_frame.pack_forget()
        self.view_passwords_frame.pack_forget()
        self.view_history_frame.pack_forget()
        self.master_password_frame.pack(fill='both', expand=1)
        self.root.geometry(MAIN_WINDOW_SIZE)
        messagebox.showinfo("Emergency Lockdown Activated!", "The application is now locked and secured. Please enter the master password to resume access.")

    def bind_shortcuts(self):
        self.root.bind('<Control-l>', self.check_and_lock)

    def check_and_lock(self, event=None):
        if not self.master_password_frame.winfo_ismapped():
            self.emergency_lockdown()

    def bind_all_events(self):
        for widget in self.root.winfo_children():
            widget.bind_all("<Key>", self.reset_inactivity_timer)
            widget.bind_all("<Button-1>", self.reset_inactivity_timer)

    def check_first_time(self):
        self.db_manager.cursor.execute("SELECT * FROM master_password WHERE id = 1")
        result = self.db_manager.cursor.fetchone()
        return result is None

    def format_phone_entry(self, event, entry=None):
        if entry is None:
            entry = self.phone_entry
        value = entry.get()
        digits = ''.join(filter(str.isdigit, value))
        formatted_value = '-'.join([digits[:3], digits[3:6], digits[6:10]]) if len(digits) > 6 else digits
        entry.delete(0, tk.END)
        entry.insert(0, formatted_value)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: [root.clipboard_clear(), root.destroy()])
    root.mainloop()
