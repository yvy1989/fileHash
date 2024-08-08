import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

def generate_hash(file_path):
    """Gera um hash SHA-256 para um arquivo."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def encrypt_data(data, key):
    """Criptografa os dados usando Fernet."""
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    """Descriptografa os dados usando Fernet."""
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode()


class MonitorHandler(FileSystemEventHandler):
    def __init__(self, file_hashes, key, callback):
        self.file_hashes = file_hashes
        self.key = key
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            new_hash = generate_hash(file_path)
            original_hash = decrypt_data(self.file_hashes[file_path], self.key)

            if new_hash != original_hash:
                self.callback(file_path)

class IntegrityMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Integridade de Arquivos")
        self.file_hashes = {}
        self.key = Fernet.generate_key()

        self.setup_gui()

    def setup_gui(self):
        self.label = tk.Label(self.root, text="Selecione os arquivos para monitorar:")
        self.label.pack(pady=10)

        self.select_button = tk.Button(self.root, text="Selecionar Arquivos", command=self.select_files)
        self.select_button.pack(pady=10)

        self.start_button = tk.Button(self.root, text="Iniciar Monitoramento", command=self.start_monitoring)
        self.start_button.pack(pady=10)

    def select_files(self):
        files = filedialog.askopenfilenames(title="Selecione os arquivos para monitorar")
        for file in files:
            file_hash = generate_hash(file)
            encrypted_hash = encrypt_data(file_hash, self.key)
            self.file_hashes[file] = encrypted_hash

    def start_monitoring(self):
        if not self.file_hashes:
            messagebox.showerror("Erro", "Nenhum arquivo foi selecionado!")
            return

        event_handler = MonitorHandler(self.file_hashes, self.key, self.alert_user)
        self.observer = Observer()
        for file_path in self.file_hashes.keys():
            directory = os.path.dirname(file_path)
            self.observer.schedule(event_handler, directory, recursive=False)
        self.observer.start()
        messagebox.showinfo("Monitoramento", "Monitoramento iniciado com sucesso!")

    def alert_user(self, file_path):
        messagebox.showwarning("Alteração Detectada", f"O arquivo {file_path} foi modificado!")

    def stop_monitoring(self):
        self.observer.stop()
        self.observer.join()

if __name__ == "__main__":
    root = tk.Tk()
    app = IntegrityMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.stop_monitoring)
    root.mainloop()
