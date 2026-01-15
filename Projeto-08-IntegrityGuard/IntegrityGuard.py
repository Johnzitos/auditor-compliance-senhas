import os
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class IntegrityGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("IntegrityGuard v2.0 - Suite de Segurança Corporativa")
        self.geometry("1000x700")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.private_key = None
        self.public_key = None
        self.recipient_pub_key = None

        self._init_ui()

    def _init_ui(self):
        self._create_sidebar()
        self._create_tabs()

    def _create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=160, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Integrity\nGuard", 
                                     font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.lbl_status = ctk.CTkLabel(self.sidebar_frame, text="Status: Pronto", 
                                     text_color="gray", wraplength=140, justify="left")
        self.lbl_status.grid(row=1, column=0, padx=10, pady=10)

    def _create_tabs(self):
        self.tabview = ctk.CTkTabview(self, width=700)
        self.tabview.grid(row=0, column=1, padx=(20, 20), pady=(20, 20), sticky="nsew")
        
        self.tab_keys = self.tabview.add("Identidade")
        self.tab_sign = self.tabview.add("Assinar")
        self.tab_verify = self.tabview.add("Verificar")
        self.tab_encrypt = self.tabview.add("Cifrar")

        self._setup_key_tab()
        self._setup_sign_tab()
        self._setup_verify_tab()
        self._setup_encrypt_tab()

    def _setup_key_tab(self):
        ctk.CTkLabel(self.tab_keys, text="Gestão de Identidade (RSA 2048)", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        ctk.CTkButton(self.tab_keys, text="Gerar Novo Par de Chaves", command=self.generate_keys, height=40).pack(pady=10)

        self.lbl_key_status = ctk.CTkLabel(self.tab_keys, text="Nenhuma chave privada carregada.", text_color="orange")
        self.lbl_key_status.pack(pady=10)

        ctk.CTkLabel(self.tab_keys, text="Carregar Identidade Existente:").pack(pady=(15,5))
        ctk.CTkButton(self.tab_keys, text="Carregar Chave Privada (.pem)", command=self.load_private_key, fg_color="transparent", border_width=2).pack(pady=5)

    def generate_keys(self):
        try:
            priv_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM", "*.pem")], title="Salvar Chave Privada")
            if not priv_path: return

            pub_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM", "*.pem")], title="Salvar Chave Pública")
            if not pub_path: return

            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()

            with open(priv_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(pub_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            self.lbl_key_status.configure(text=f"Identidade Ativa: {os.path.basename(priv_path)}", text_color="#2cc985")
            self._log("Chaves geradas com sucesso.")
        except Exception as e: messagebox.showerror("Erro", str(e))

    def load_private_key(self):
        filename = filedialog.askopenfilename(filetypes=[("PEM", "*.pem")])
        if filename:
            try:
                with open(filename, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None)
                self.public_key = self.private_key.public_key()
                self.lbl_key_status.configure(text="Chave Privada Carregada.", text_color="#2cc985")
                self._log("Identidade carregada.")
            except Exception as e: messagebox.showerror("Erro", str(e))

    def _setup_sign_tab(self):
        ctk.CTkLabel(self.tab_sign, text="Assinatura Digital", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        ctk.CTkButton(self.tab_sign, text="Selecionar Arquivo para Assinar", command=self.sign_file, height=50, fg_color="#E53935").pack(pady=30)

    def sign_file(self):
        if not self.private_key: return messagebox.showwarning("Erro", "Carregue sua Chave Privada primeiro.")
        path = filedialog.askopenfilename()
        if path:
            try:
                with open(path, "rb") as f: data = f.read()
                signature = self.private_key.sign(
                    data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                with open(path + ".sig", "wb") as f: f.write(signature)
                messagebox.showinfo("Sucesso", "Arquivo assinado (.sig gerado).")
                self._log(f"Assinado: {os.path.basename(path)}")
            except Exception as e: messagebox.showerror("Erro", str(e))

    def _setup_verify_tab(self):
        ctk.CTkLabel(self.tab_verify, text="Verificação de Integridade", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        ctk.CTkButton(self.tab_verify, text="Carregar Chave Pública do Remetente", command=self.load_verifier_key).pack(pady=10)
        self.lbl_verifier_status = ctk.CTkLabel(self.tab_verify, text="Nenhuma chave pública carregada.", text_color="gray")
        self.lbl_verifier_status.pack(pady=5)
        
        self.btn_verify = ctk.CTkButton(self.tab_verify, text="Verificar Arquivo", command=self.verify_file, state="disabled")
        self.btn_verify.pack(pady=20)
        self.lbl_verify_result = ctk.CTkLabel(self.tab_verify, text="", font=ctk.CTkFont(size=24, weight="bold"))
        self.lbl_verify_result.pack(pady=10)

    def load_verifier_key(self):
        f = filedialog.askopenfilename(filetypes=[("PEM", "*.pem")])
        if f:
            try:
                with open(f, "rb") as k: self.recipient_pub_key = serialization.load_pem_public_key(k.read())
                self.lbl_verifier_status.configure(text="Chave Pública Carregada.", text_color="#2cc985")
                self.btn_verify.configure(state="normal")
            except: messagebox.showerror("Erro", "Chave Inválida.")

    def verify_file(self):
        f_path = filedialog.askopenfilename(title="Selecione o Arquivo Original")
        if not f_path: return
        s_path = f_path + ".sig"
        if not os.path.exists(s_path):
            s_path = filedialog.askopenfilename(title="Selecione a Assinatura (.sig)")
            if not s_path: return

        try:
            with open(f_path, "rb") as f: data = f.read()
            with open(s_path, "rb") as f: sig = f.read()
            self.recipient_pub_key.verify(
                sig, data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            self.lbl_verify_result.configure(text="✔ INTEGRO", text_color="#00ff00")
        except:
            self.lbl_verify_result.configure(text="⚠ ADULTERADO / INVÁLIDO", text_color="#ff0000")

    def _setup_encrypt_tab(self):
        self.tab_encrypt.grid_columnconfigure(0, weight=1)
        self.tab_encrypt.grid_columnconfigure(1, weight=1)

        frame_enc = ctk.CTkFrame(self.tab_encrypt)
        frame_enc.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(frame_enc, text="ENVIAR (Cifrar)", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        ctk.CTkButton(frame_enc, text="Carregar Chave Pública do Destinatário", command=self.load_dest_pub_key, fg_color="#444").pack(pady=5)
        self.lbl_enc_status = ctk.CTkLabel(frame_enc, text="Pendente...", text_color="gray")
        self.lbl_enc_status.pack(pady=5)

        ctk.CTkLabel(frame_enc, text="Operação:", text_color="gray").pack(pady=(20,5))
        ctk.CTkButton(frame_enc, text="🔒 Apenas Criptografar", command=lambda: self.encrypt_workflow(sign=False), fg_color="#1f6aa5").pack(pady=5)
        ctk.CTkButton(frame_enc, text="🔒 Criptografar + ✒️ Assinar", command=lambda: self.encrypt_workflow(sign=True), fg_color="#8E24AA").pack(pady=5)

        frame_dec = ctk.CTkFrame(self.tab_encrypt)
        frame_dec.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        ctk.CTkLabel(frame_dec, text="RECEBER (Decifrar)", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        ctk.CTkButton(frame_dec, text="🔓 Descriptografar Arquivo", command=self.decrypt_workflow, fg_color="#2cc985", text_color="black").pack(pady=20)

    def load_dest_pub_key(self):
        f = filedialog.askopenfilename(title="Chave Pública do Destinatário", filetypes=[("PEM", "*.pem")])
        if f:
            with open(f, "rb") as k: self.recipient_pub_key = serialization.load_pem_public_key(k.read())
            self.lbl_enc_status.configure(text="Chave Carregada", text_color="#2cc985")

    def encrypt_workflow(self, sign=False):
        if not self.recipient_pub_key:
            return messagebox.showwarning("Erro", "Carregue a Chave Pública do Destinatário primeiro.")
        
        if sign and not self.private_key:
            return messagebox.showwarning("Erro", "Carregue SUA Chave Privada para assinar.")

        file_path = filedialog.askopenfilename(title="Selecione o Arquivo")
        if not file_path: return

        try:
            with open(file_path, "rb") as f: original_data = f.read()

            if sign:
                signature = self.private_key.sign(
                    original_data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                with open(file_path + ".sig", "wb") as f: f.write(signature)
            
            fernet_key = Fernet.generate_key()
            fernet = Fernet(fernet_key)
            encrypted_data = fernet.encrypt(original_data)
            
            enc_fernet_key = self.recipient_pub_key.encrypt(
                fernet_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            with open(file_path + ".enc", "wb") as f: f.write(encrypted_data)
            with open(file_path + ".key", "wb") as f: f.write(enc_fernet_key)

            messagebox.showinfo("Sucesso", "Arquivo processado com sucesso.")
            self._log(f"Cifrado{' & Assinado' if sign else ''}: {os.path.basename(file_path)}")

        except Exception as e: messagebox.showerror("Erro Crítico", str(e))

    def decrypt_workflow(self):
        if not self.private_key:
            return messagebox.showwarning("Erro", "Carregue SUA Chave Privada para decifrar.")

        enc_path = filedialog.askopenfilename(title="Selecione o arquivo .enc", filetypes=[("Encrypted", "*.enc")])
        if not enc_path: return

        key_path = enc_path.replace(".enc", ".key")
        if not os.path.exists(key_path):
            key_path = filedialog.askopenfilename(title="Selecione o arquivo chave (.key)")
            if not key_path: return

        try:
            with open(key_path, "rb") as f: enc_fernet_key = f.read()

            fernet_key = self.private_key.decrypt(
                enc_fernet_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            fernet = Fernet(fernet_key)
            with open(enc_path, "rb") as f: encrypted_data = f.read()
            original_data = fernet.decrypt(encrypted_data)

            save_path = enc_path.replace(".enc", "") 
            if os.path.exists(save_path): save_path += ".restored"
            
            with open(save_path, "wb") as f: f.write(original_data)

            messagebox.showinfo("Sucesso", f"Decifrado em: {os.path.basename(save_path)}")
            self._log(f"Decifrado: {os.path.basename(save_path)}")

        except Exception:
            messagebox.showerror("Erro", "Falha na descriptografia. Chave incorreta ou arquivo corrompido.")

    def _log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.lbl_status.configure(text=f"Log [{timestamp}]: {message}")

if __name__ == "__main__":
    app = IntegrityGuardApp()
    app.mainloop()