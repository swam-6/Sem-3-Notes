import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading

# ── Crypto imports ──────────────────────────────────────────────────────────
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, base64

# ════════════════════════════════════════════════════════════════════════════
# THEME
# ════════════════════════════════════════════════════════════════════════════
BG        = "#0d0d0d"
PANEL     = "#141414"
CARD      = "#1a1a1a"
BORDER    = "#2a2a2a"
ACCENT    = "#00ff88"
ACCENT2   = "#00ccff"
WARN      = "#ff4466"
TEXT      = "#e8e8e8"
MUTED     = "#666666"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI", 13, "bold")
FONT_TINY = ("Segoe UI", 8)

# ════════════════════════════════════════════════════════════════════════════
# CRYPTO ENGINE
# ════════════════════════════════════════════════════════════════════════════
class CryptoEngine:
    def __init__(self):
        self.rsa_private = None
        self.rsa_public  = None
        self.dsa_private = None
        self.dsa_public  = None
        self.aes_key     = None

    # ── RSA ─────────────────────────────────────────────────────────────────
    def generate_rsa_keys(self, key_size=2048):
        self.rsa_private = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend())
        self.rsa_public = self.rsa_private.public_key()
        return self._serialize_rsa()

    def _serialize_rsa(self):
        priv = self.rsa_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        pub = self.rsa_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return priv, pub

    def rsa_encrypt(self, plaintext: str) -> str:
        if not self.rsa_public:
            raise ValueError("Generate RSA keys first.")
        ct = self.rsa_public.encrypt(
            plaintext.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(ct).decode()

    def rsa_decrypt(self, ciphertext_b64: str) -> str:
        if not self.rsa_private:
            raise ValueError("Generate RSA keys first.")
        ct = base64.b64decode(ciphertext_b64)
        pt = self.rsa_private.decrypt(
            ct,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None))
        return pt.decode()

    # ── DSA ─────────────────────────────────────────────────────────────────
    def generate_dsa_keys(self, key_size=2048):
        self.dsa_private = dsa.generate_private_key(
            key_size=key_size, backend=default_backend())
        self.dsa_public = self.dsa_private.public_key()
        priv = self.dsa_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        pub = self.dsa_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return priv, pub

    def dsa_sign(self, message: str) -> str:
        if not self.dsa_private:
            raise ValueError("Generate DSA keys first.")
        sig = self.dsa_private.sign(message.encode(), hashes.SHA256())
        return base64.b64encode(sig).decode()

    def dsa_verify(self, message: str, signature_b64: str) -> bool:
        if not self.dsa_public:
            raise ValueError("Generate DSA keys first.")
        sig = base64.b64decode(signature_b64)
        try:
            self.dsa_public.verify(sig, message.encode(), hashes.SHA256())
            return True
        except Exception:
            return False

    # ── AES ─────────────────────────────────────────────────────────────────
    def generate_aes_key(self):
        self.aes_key = os.urandom(32)
        return base64.b64encode(self.aes_key).decode()

    def aes_encrypt(self, plaintext: str) -> str:
        if not self.aes_key:
            raise ValueError("Generate AES key first.")
        iv = os.urandom(16)
        padded = plaintext.encode()
        # simple PKCS7 padding
        pad_len = 16 - len(padded) % 16
        padded += bytes([pad_len] * pad_len)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return base64.b64encode(iv + ct).decode()

    def aes_decrypt(self, ciphertext_b64: str) -> str:
        if not self.aes_key:
            raise ValueError("Generate AES key first.")
        raw = base64.b64decode(ciphertext_b64)
        iv, ct = raw[:16], raw[16:]
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        pad_len = padded[-1]
        return padded[:-pad_len].decode()




# ════════════════════════════════════════════════════════════════════════════
# WIDGETS
# ════════════════════════════════════════════════════════════════════════════
def styled_btn(parent, text, cmd, color=ACCENT, width=18):
    btn = tk.Button(parent, text=text, command=cmd,
                    bg=CARD, fg=color, activebackground=BORDER,
                    activeforeground=color, relief="flat",
                    font=FONT_UI, cursor="hand2", width=width,
                    highlightthickness=1, highlightbackground=color,
                    pady=6)
    btn.bind("<Enter>", lambda e: btn.config(bg=BORDER))
    btn.bind("<Leave>", lambda e: btn.config(bg=CARD))
    return btn

def text_area(parent, h=4, width=72, mono=True):
    t = scrolledtext.ScrolledText(parent, height=h, width=width,
        bg="#0f0f0f", fg=TEXT, insertbackground=ACCENT,
        font=FONT_MONO if mono else FONT_UI,
        relief="flat", wrap="word",
        highlightthickness=1, highlightbackground=BORDER)
    return t

def label(parent, text, color=MUTED, size=9, bold=False):
    style = ("Segoe UI", size, "bold") if bold else ("Segoe UI", size)
    return tk.Label(parent, text=text, bg=PANEL, fg=color, font=style)

def section_label(parent, text):
    f = tk.Frame(parent, bg=PANEL)
    tk.Label(f, text="▸ " + text, bg=PANEL, fg=ACCENT,
             font=("Segoe UI", 10, "bold")).pack(side="left")
    return f

def separator(parent):
    return tk.Frame(parent, bg=BORDER, height=1)


# ════════════════════════════════════════════════════════════════════════════
# STATUS BAR
# ════════════════════════════════════════════════════════════════════════════
class StatusBar(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#0a0a0a", height=26)
        self._var = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self._var, bg="#0a0a0a", fg=MUTED,
                 font=FONT_TINY, anchor="w").pack(side="left", padx=10)
        # indicator dots
        self._dots = []
        for c in [ACCENT, ACCENT2, WARN]:
            d = tk.Label(self, text="●", bg="#0a0a0a", fg=c, font=("Segoe UI", 8))
            d.pack(side="right", padx=4)
            self._dots.append(d)

    def set(self, msg, color=TEXT):
        self._var.set(f"  {msg}")


# ════════════════════════════════════════════════════════════════════════════
# TABS
# ════════════════════════════════════════════════════════════════════════════

# ── RSA Tab ──────────────────────────────────────────────────────────────────
class RSATab(tk.Frame):
    def __init__(self, parent, engine: CryptoEngine, status):
        super().__init__(parent, bg=PANEL)
        self.engine = engine
        self.status = status
        self._build()

    def _build(self):
        pad = {"padx": 16, "pady": 6}

        # Keys row
        section_label(self, "Key Generation").pack(anchor="w", **pad)

        kf = tk.Frame(self, bg=PANEL)
        kf.pack(fill="x", **pad)
        tk.Label(kf, text="Key Size:", bg=PANEL, fg=MUTED, font=FONT_UI).pack(side="left")
        self.key_size = ttk.Combobox(kf, values=["1024", "2048", "4096"],
                                     width=8, state="readonly", font=FONT_UI)
        self.key_size.set("2048")
        self.key_size.pack(side="left", padx=8)
        styled_btn(kf, "⚙  Generate Keys", self._gen_keys, width=20).pack(side="left", padx=8)

        separator(self).pack(fill="x", padx=16, pady=4)

        # Key display
        krow = tk.Frame(self, bg=PANEL)
        krow.pack(fill="x", padx=16)
        for col, title in enumerate(["Private Key", "Public Key"]):
            cf = tk.Frame(krow, bg=PANEL)
            cf.grid(row=0, column=col, padx=4, sticky="nsew")
            krow.columnconfigure(col, weight=1)
            label(cf, title, color=ACCENT2, size=9).pack(anchor="w")
            t = text_area(cf, h=6, width=44)
            t.pack(fill="x")
            setattr(self, f"{'priv' if col==0 else 'pub'}_key_box", t)

        separator(self).pack(fill="x", padx=16, pady=8)

        # Encrypt
        section_label(self, "Encrypt").pack(anchor="w", **pad)
        label(self, "Plaintext").pack(anchor="w", padx=16)
        self.plain_box = text_area(self, h=3)
        self.plain_box.pack(fill="x", padx=16, pady=2)
        styled_btn(self, "🔒  Encrypt", self._encrypt).pack(anchor="w", padx=16, pady=4)
        label(self, "Ciphertext (Base64)").pack(anchor="w", padx=16)
        self.cipher_box = text_area(self, h=3)
        self.cipher_box.pack(fill="x", padx=16, pady=2)

        separator(self).pack(fill="x", padx=16, pady=8)

        # Decrypt
        section_label(self, "Decrypt").pack(anchor="w", **pad)
        label(self, "Ciphertext (Base64) — paste here or auto-filled above").pack(anchor="w", padx=16)
        self.dec_in_box = text_area(self, h=3)
        self.dec_in_box.pack(fill="x", padx=16, pady=2)
        styled_btn(self, "🔓  Decrypt", self._decrypt, color=ACCENT2).pack(anchor="w", padx=16, pady=4)
        label(self, "Recovered Plaintext").pack(anchor="w", padx=16)
        self.dec_out_box = text_area(self, h=3)
        self.dec_out_box.pack(fill="x", padx=16, pady=2)

    def _gen_keys(self):
        def task():
            self.status.set("Generating RSA keys…")
            try:
                size = int(self.key_size.get())
                priv, pub = self.engine.generate_rsa_keys(size)
                for box, val in [(self.priv_key_box, priv), (self.pub_key_box, pub)]:
                    box.delete("1.0", "end"); box.insert("1.0", val)
                self.status.set(f"RSA {size}-bit keys generated ✓")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        threading.Thread(target=task, daemon=True).start()

    def _encrypt(self):
        try:
            pt = self.plain_box.get("1.0", "end").strip()
            ct = self.engine.rsa_encrypt(pt)
            self.cipher_box.delete("1.0", "end"); self.cipher_box.insert("1.0", ct)
            self.dec_in_box.delete("1.0", "end"); self.dec_in_box.insert("1.0", ct)
            self.status.set("RSA encryption successful ✓")
        except Exception as e:
            messagebox.showerror("Encrypt Error", str(e))

    def _decrypt(self):
        try:
            ct = self.dec_in_box.get("1.0", "end").strip()
            pt = self.engine.rsa_decrypt(ct)
            self.dec_out_box.delete("1.0", "end"); self.dec_out_box.insert("1.0", pt)
            self.status.set("RSA decryption successful ✓")
        except Exception as e:
            messagebox.showerror("Decrypt Error", str(e))


# ── DSA Tab ──────────────────────────────────────────────────────────────────
class DSATab(tk.Frame):
    def __init__(self, parent, engine: CryptoEngine, status):
        super().__init__(parent, bg=PANEL)
        self.engine = engine
        self.status = status
        self._build()

    def _build(self):
        pad = {"padx": 16, "pady": 6}
        section_label(self, "Key Generation").pack(anchor="w", **pad)

        kf = tk.Frame(self, bg=PANEL)
        kf.pack(fill="x", **pad)
        tk.Label(kf, text="Key Size:", bg=PANEL, fg=MUTED, font=FONT_UI).pack(side="left")
        self.key_size = ttk.Combobox(kf, values=["1024", "2048", "3072"],
                                     width=8, state="readonly", font=FONT_UI)
        self.key_size.set("2048")
        self.key_size.pack(side="left", padx=8)
        styled_btn(kf, "⚙  Generate Keys", self._gen_keys, width=20).pack(side="left", padx=8)

        separator(self).pack(fill="x", padx=16, pady=4)

        krow = tk.Frame(self, bg=PANEL)
        krow.pack(fill="x", padx=16)
        for col, title in enumerate(["Private Key", "Public Key"]):
            cf = tk.Frame(krow, bg=PANEL)
            cf.grid(row=0, column=col, padx=4, sticky="nsew")
            krow.columnconfigure(col, weight=1)
            label(cf, title, color=ACCENT2, size=9).pack(anchor="w")
            t = text_area(cf, h=6, width=44)
            t.pack(fill="x")
            setattr(self, f"{'priv' if col==0 else 'pub'}_key_box", t)

        separator(self).pack(fill="x", padx=16, pady=8)

        section_label(self, "Sign Message").pack(anchor="w", **pad)
        label(self, "Message").pack(anchor="w", padx=16)
        self.msg_box = text_area(self, h=3)
        self.msg_box.pack(fill="x", padx=16, pady=2)
        styled_btn(self, "✍  Sign", self._sign).pack(anchor="w", padx=16, pady=4)
        label(self, "Signature (Base64)").pack(anchor="w", padx=16)
        self.sig_box = text_area(self, h=3)
        self.sig_box.pack(fill="x", padx=16, pady=2)

        separator(self).pack(fill="x", padx=16, pady=8)

        section_label(self, "Verify Signature").pack(anchor="w", **pad)
        label(self, "Message to Verify").pack(anchor="w", padx=16)
        self.ver_msg_box = text_area(self, h=2)
        self.ver_msg_box.pack(fill="x", padx=16, pady=2)
        label(self, "Signature (Base64)").pack(anchor="w", padx=16)
        self.ver_sig_box = text_area(self, h=2)
        self.ver_sig_box.pack(fill="x", padx=16, pady=2)
        bf = tk.Frame(self, bg=PANEL)
        bf.pack(anchor="w", padx=16, pady=4)
        styled_btn(bf, "✔  Verify", self._verify, color=ACCENT2).pack(side="left")
        self.result_lbl = tk.Label(bf, text="", bg=PANEL, font=("Segoe UI", 11, "bold"))
        self.result_lbl.pack(side="left", padx=12)

    def _gen_keys(self):
        def task():
            self.status.set("Generating DSA keys…")
            try:
                size = int(self.key_size.get())
                priv, pub = self.engine.generate_dsa_keys(size)
                for box, val in [(self.priv_key_box, priv), (self.pub_key_box, pub)]:
                    box.delete("1.0", "end"); box.insert("1.0", val)
                self.status.set(f"DSA {size}-bit keys generated ✓")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        threading.Thread(target=task, daemon=True).start()

    def _sign(self):
        try:
            msg = self.msg_box.get("1.0", "end").strip()
            sig = self.engine.dsa_sign(msg)
            self.sig_box.delete("1.0", "end"); self.sig_box.insert("1.0", sig)
            self.ver_msg_box.delete("1.0", "end"); self.ver_msg_box.insert("1.0", msg)
            self.ver_sig_box.delete("1.0", "end"); self.ver_sig_box.insert("1.0", sig)
            self.status.set("Message signed ✓")
        except Exception as e:
            messagebox.showerror("Sign Error", str(e))

    def _verify(self):
        try:
            msg = self.ver_msg_box.get("1.0", "end").strip()
            sig = self.ver_sig_box.get("1.0", "end").strip()
            ok = self.engine.dsa_verify(msg, sig)
            color = ACCENT if ok else WARN
            self.result_lbl.config(text="✔ VALID" if ok else "✘ INVALID", fg=color)
            self.status.set("Signature valid ✓" if ok else "Signature INVALID ✗")
        except Exception as e:
            messagebox.showerror("Verify Error", str(e))


# ── AES Tab ──────────────────────────────────────────────────────────────────
class AESTab(tk.Frame):
    def __init__(self, parent, engine: CryptoEngine, status):
        super().__init__(parent, bg=PANEL)
        self.engine = engine
        self.status = status
        self._build()

    def _build(self):
        pad = {"padx": 16, "pady": 6}
        section_label(self, "AES-256-CBC — Symmetric Encryption").pack(anchor="w", **pad)

        kf = tk.Frame(self, bg=PANEL)
        kf.pack(fill="x", **pad)
        styled_btn(kf, "⚙  Generate Key", self._gen_key, width=20).pack(side="left")
        label(kf, "  256-bit random key", size=9).pack(side="left")

        label(self, "AES Key (Base64)").pack(anchor="w", padx=16)
        self.key_box = text_area(self, h=2)
        self.key_box.pack(fill="x", padx=16, pady=2)

        separator(self).pack(fill="x", padx=16, pady=8)

        section_label(self, "Encrypt").pack(anchor="w", **pad)
        label(self, "Plaintext").pack(anchor="w", padx=16)
        self.plain_box = text_area(self, h=4)
        self.plain_box.pack(fill="x", padx=16, pady=2)
        styled_btn(self, "🔒  Encrypt", self._encrypt).pack(anchor="w", padx=16, pady=4)
        label(self, "Ciphertext (Base64, IV prepended)").pack(anchor="w", padx=16)
        self.cipher_box = text_area(self, h=4)
        self.cipher_box.pack(fill="x", padx=16, pady=2)

        separator(self).pack(fill="x", padx=16, pady=8)

        section_label(self, "Decrypt").pack(anchor="w", **pad)
        label(self, "Ciphertext (Base64)").pack(anchor="w", padx=16)
        self.dec_in_box = text_area(self, h=4)
        self.dec_in_box.pack(fill="x", padx=16, pady=2)
        styled_btn(self, "🔓  Decrypt", self._decrypt, color=ACCENT2).pack(anchor="w", padx=16, pady=4)
        label(self, "Recovered Plaintext").pack(anchor="w", padx=16)
        self.dec_out_box = text_area(self, h=4)
        self.dec_out_box.pack(fill="x", padx=16, pady=2)

    def _gen_key(self):
        k = self.engine.generate_aes_key()
        self.key_box.delete("1.0", "end"); self.key_box.insert("1.0", k)
        self.status.set("AES-256 key generated ✓")

    def _encrypt(self):
        try:
            pt = self.plain_box.get("1.0", "end").strip()
            ct = self.engine.aes_encrypt(pt)
            self.cipher_box.delete("1.0", "end"); self.cipher_box.insert("1.0", ct)
            self.dec_in_box.delete("1.0", "end"); self.dec_in_box.insert("1.0", ct)
            self.status.set("AES encryption successful ✓")
        except Exception as e:
            messagebox.showerror("Encrypt Error", str(e))

    def _decrypt(self):
        try:
            ct = self.dec_in_box.get("1.0", "end").strip()
            pt = self.engine.aes_decrypt(ct)
            self.dec_out_box.delete("1.0", "end"); self.dec_out_box.insert("1.0", pt)
            self.status.set("AES decryption successful ✓")
        except Exception as e:
            messagebox.showerror("Decrypt Error", str(e))





# ════════════════════════════════════════════════════════════════════════════
# MAIN APP
# ════════════════════════════════════════════════════════════════════════════
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoLab — Encryption & Hashing Tool")
        self.geometry("860x720")
        self.minsize(780, 600)
        self.configure(bg=BG)
        self.engine = CryptoEngine()
        self._style_ttk()
        self._build()

    def _style_ttk(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=0)
        s.configure("TNotebook.Tab",
                    background=CARD, foreground=MUTED,
                    font=("Segoe UI", 10), padding=[16, 8],
                    borderwidth=0)
        s.map("TNotebook.Tab",
              background=[("selected", PANEL), ("active", BORDER)],
              foreground=[("selected", ACCENT), ("active", TEXT)])
        s.configure("TCombobox", fieldbackground=CARD, background=CARD,
                    foreground=TEXT, arrowcolor=ACCENT,
                    selectbackground=BORDER, selectforeground=TEXT)

    def _build(self):
        # ── Header ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg="#0a0a0a", height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔐  CryptoLab", bg="#0a0a0a",
                 fg=ACCENT, font=("Courier New", 16, "bold")).pack(side="left", padx=20, pady=10)
        tk.Label(hdr, text="RSA · DSA · AES",
                 bg="#0a0a0a", fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        tk.Label(hdr, text="v1.0 · Python cryptography",
                 bg="#0a0a0a", fg="#333", font=("Segoe UI", 8)).pack(side="right", padx=20)

        # ── Notebook ─────────────────────────────────────────────────────────
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=0, pady=0)

        # ── Status bar ───────────────────────────────────────────────────────
        self.status = StatusBar(self)
        self.status.pack(fill="x", side="bottom")

        # ── Tabs ─────────────────────────────────────────────────────────────
        tabs = [
            ("  RSA  ",    RSATab),
            ("  DSA  ",    DSATab),
            ("  AES  ",    AESTab),
        ]
        for title, cls in tabs:
            frame = tk.Frame(self.nb, bg=PANEL)
            canvas = tk.Canvas(frame, bg=PANEL, highlightthickness=0)
            sb = tk.Scrollbar(frame, orient="vertical", command=canvas.yview,
                              bg=CARD, troughcolor=BG, width=10)
            inner = cls(canvas, self.engine, self.status)
            canvas.create_window((0, 0), window=inner, anchor="nw")
            canvas.configure(yscrollcommand=sb.set)
            inner.bind("<Configure>",
                       lambda e, c=canvas: c.configure(scrollregion=c.bbox("all")))
            canvas.bind("<MouseWheel>",
                        lambda e, c=canvas: c.yview_scroll(-1*(e.delta//120), "units"))
            sb.pack(side="right", fill="y")
            canvas.pack(side="left", fill="both", expand=True)
            self.nb.add(frame, text=title)


# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
