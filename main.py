"""
=============================================================================
  File Encryption & Decryption Tool
  ----------------------------------
  A desktop application that allows users to encrypt and decrypt files
  securely using AES-256-CBC encryption and a user-supplied password.

  Technology Stack:
      • Python 3
      • Tkinter   – graphical user interface
      • PyCryptodome – AES encryption primitives
      • hashlib   – PBKDF2 key derivation
      • os        – file-system helpers

  Security highlights:
      • AES-256 in CBC mode
      • PBKDF2-HMAC-SHA256 key derivation (600 000 iterations)
      • Random 16-byte salt per encryption
      • Random 16-byte IV per encryption

  Encrypted file layout (binary):
      [ 16-byte salt ][ 16-byte IV ][ AES-CBC ciphertext (PKCS7 padded) ]
=============================================================================
"""

# ── Standard-library imports ────────────────────────────────────────────────
import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ── Third-party imports (PyCryptodome) ──────────────────────────────────────
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ═══════════════════════════════════════════════════════════════════════════
#  ENCRYPTION / DECRYPTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════

# Number of PBKDF2 iterations – OWASP recommends ≥600 000 for SHA-256
PBKDF2_ITERATIONS = 600_000
# AES block size is always 16 bytes
AES_BLOCK_SIZE = AES.block_size  # 16
# Salt length in bytes
SALT_LENGTH = 16
# AES-256 key length in bytes
KEY_LENGTH = 32


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from *password* using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    password : str
        The user-supplied password (plain text).
    salt : bytes
        A random 16-byte salt unique to each encryption operation.

    Returns
    -------
    bytes
        A 32-byte (256-bit) derived key suitable for AES-256.
    """
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=KEY_LENGTH,
    )


def encrypt_file(file_path: str, password: str) -> str:
    """
    Encrypt a file using AES-256-CBC with a password-derived key.

    Steps
    -----
    1. Generate a random 16-byte salt.
    2. Generate a random 16-byte IV (initialisation vector).
    3. Derive a 256-bit key from the password + salt via PBKDF2.
    4. Read the entire plaintext file.
    5. PKCS7-pad the plaintext to AES block size.
    6. Encrypt using AES-256-CBC.
    7. Write salt ‖ IV ‖ ciphertext to *<original_name>.enc*.

    Parameters
    ----------
    file_path : str
        Absolute path of the file to encrypt.
    password : str
        User-supplied password.

    Returns
    -------
    str
        Path to the newly created encrypted file.

    Raises
    ------
    FileNotFoundError
        If *file_path* does not exist.
    ValueError
        If the password is empty.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # 1. Random salt & IV
    salt = get_random_bytes(SALT_LENGTH)
    iv = get_random_bytes(AES_BLOCK_SIZE)

    # 2. Derive key
    key = derive_key(password, salt)

    # 3. Read plaintext
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # 4. Pad & encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES_BLOCK_SIZE))

    # 5. Write encrypted file  →  salt ‖ IV ‖ ciphertext
    enc_path = file_path + ".enc"
    with open(enc_path, "wb") as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

    return enc_path


def decrypt_file(file_path: str, password: str) -> str:
    """
    Decrypt a *.enc* file previously created by *encrypt_file()*.

    Steps
    -----
    1. Read salt (first 16 bytes) and IV (next 16 bytes) from the file.
    2. Derive the AES-256 key from the password + salt.
    3. Decrypt the remaining ciphertext with AES-256-CBC.
    4. Remove PKCS7 padding.
    5. Write the recovered plaintext, stripping the *.enc* extension.

    Parameters
    ----------
    file_path : str
        Path to the encrypted *.enc* file.
    password : str
        User-supplied password (must match the one used for encryption).

    Returns
    -------
    str
        Path to the restored plaintext file.

    Raises
    ------
    FileNotFoundError
        If *file_path* does not exist.
    ValueError
        If the password is incorrect or the file is corrupt.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        # 1. Extract salt and IV
        salt = f.read(SALT_LENGTH)
        iv = f.read(AES_BLOCK_SIZE)
        ciphertext = f.read()

    # Minimal sanity check
    if len(salt) < SALT_LENGTH or len(iv) < AES_BLOCK_SIZE or len(ciphertext) == 0:
        raise ValueError("The selected file is not a valid encrypted file.")

    # 2. Derive key
    key = derive_key(password, salt)

    # 3. Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)
    except (ValueError, KeyError):
        raise ValueError(
            "Decryption failed – the password is incorrect or the file is corrupt."
        )

    # 4. Write restored file (strip the .enc extension)
    if file_path.endswith(".enc"):
        dec_path = file_path[:-4]
    else:
        dec_path = file_path + ".dec"

    with open(dec_path, "wb") as f:
        f.write(plaintext)

    return dec_path


# ═══════════════════════════════════════════════════════════════════════════
#  GUI APPLICATION CLASS
# ═══════════════════════════════════════════════════════════════════════════

class EncryptionApp:
    """
    Main application window built with Tkinter.

    The interface uses a clean *light-blue & white* theme and exposes
    five main actions: Select File, Encrypt, Decrypt, Clear, and Exit.
    """

    # ── Colour palette ──────────────────────────────────────────────────
    BG_PRIMARY = "#E3F2FD"       # Light blue background
    BG_SECONDARY = "#FFFFFF"     # White card / input background
    FG_TEXT = "#1A237E"          # Dark indigo text
    FG_MUTED = "#546E7A"        # Muted grey-blue for secondary text
    ACCENT = "#1565C0"          # Strong blue for headings / accents
    BTN_SELECT = "#1976D2"      # Blue – Select File
    BTN_ENCRYPT = "#2E7D32"     # Green – Encrypt
    BTN_DECRYPT = "#E65100"     # Orange – Decrypt
    BTN_CLEAR = "#546E7A"       # Grey – Clear
    BTN_EXIT = "#C62828"        # Red – Exit
    BTN_FG = "#FFFFFF"          # White text on buttons
    ENTRY_BORDER = "#90CAF9"    # Light blue border for entries
    CARD_SHADOW = "#BBDEFB"     # Subtle shadow tone

    # ── Fonts ───────────────────────────────────────────────────────────
    FONT_TITLE = ("Segoe UI", 18, "bold")
    FONT_SUBTITLE = ("Segoe UI", 10)
    FONT_LABEL = ("Segoe UI", 11)
    FONT_ENTRY = ("Segoe UI", 11)
    FONT_BUTTON = ("Segoe UI", 11, "bold")
    FONT_PATH = ("Consolas", 10)
    FONT_STATUS = ("Segoe UI", 9)

    def __init__(self, root: tk.Tk) -> None:
        """Initialise the application window and build all widgets."""
        self.root = root
        self.selected_file: str = ""  # Stores the currently selected file path

        # ── Window configuration ────────────────────────────────────────
        self.root.title("File Encryption & Decryption Tool")
        self.root.geometry("620x580")
        self.root.resizable(False, False)
        self.root.configure(bg=self.BG_PRIMARY)

        # Try to set a window icon (silently skip if unavailable)
        try:
            self.root.iconbitmap(default="")
        except tk.TclError:
            pass

        # ── Build the interface ─────────────────────────────────────────
        self._build_header()
        self._build_file_section()
        self._build_password_section()
        self._build_action_buttons()
        self._build_status_bar()

    # ────────────────────────────────────────────────────────────────────
    #  WIDGET BUILDERS
    # ────────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        """Create the title bar at the top of the window."""
        header = tk.Frame(self.root, bg=self.ACCENT, height=80)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Main title
        tk.Label(
            header,
            text="🔐  File Encryption & Decryption Tool",
            font=self.FONT_TITLE,
            bg=self.ACCENT,
            fg=self.BTN_FG,
        ).pack(pady=(18, 2))

        # Subtitle
        tk.Label(
            header,
            text="Secure your files with AES-256 encryption",
            font=self.FONT_SUBTITLE,
            bg=self.ACCENT,
            fg="#BBDEFB",
        ).pack()

    def _build_file_section(self) -> None:
        """
        Build the 'Select File' card: a button and a read-only entry
        that displays the chosen file path.
        """
        # Outer card frame
        card = tk.Frame(self.root, bg=self.BG_SECONDARY, bd=0,
                        highlightbackground=self.CARD_SHADOW,
                        highlightthickness=1)
        card.pack(fill="x", padx=24, pady=(20, 8))

        inner = tk.Frame(card, bg=self.BG_SECONDARY)
        inner.pack(fill="x", padx=16, pady=14)

        # Section label
        tk.Label(
            inner, text="📁  Select a File", font=self.FONT_LABEL,
            bg=self.BG_SECONDARY, fg=self.ACCENT, anchor="w",
        ).pack(fill="x")

        # Row: [Select File button] [file-path entry]
        row = tk.Frame(inner, bg=self.BG_SECONDARY)
        row.pack(fill="x", pady=(8, 0))

        btn_select = tk.Button(
            row, text="Browse…", font=self.FONT_BUTTON,
            bg=self.BTN_SELECT, fg=self.BTN_FG,
            activebackground="#1E88E5", activeforeground=self.BTN_FG,
            relief="flat", cursor="hand2", padx=16, pady=4,
            command=self.select_file,
        )
        btn_select.pack(side="left")

        # File-path display (read-only style)
        self.file_var = tk.StringVar(value="No file selected")
        self.file_entry = tk.Entry(
            row, textvariable=self.file_var, font=self.FONT_PATH,
            state="readonly", readonlybackground=self.BG_PRIMARY,
            fg=self.FG_MUTED, relief="flat", bd=0,
        )
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(12, 0))

    def _build_password_section(self) -> None:
        """
        Build the 'Password' card with a password entry and a
        show/hide toggle button.
        """
        card = tk.Frame(self.root, bg=self.BG_SECONDARY, bd=0,
                        highlightbackground=self.CARD_SHADOW,
                        highlightthickness=1)
        card.pack(fill="x", padx=24, pady=8)

        inner = tk.Frame(card, bg=self.BG_SECONDARY)
        inner.pack(fill="x", padx=16, pady=14)

        # Section label
        tk.Label(
            inner, text="🔑  Enter Password", font=self.FONT_LABEL,
            bg=self.BG_SECONDARY, fg=self.ACCENT, anchor="w",
        ).pack(fill="x")

        # Row: [password entry] [show/hide button]
        row = tk.Frame(inner, bg=self.BG_SECONDARY)
        row.pack(fill="x", pady=(8, 0))

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            row, textvariable=self.password_var, font=self.FONT_ENTRY,
            show="●", relief="solid", bd=1,
            highlightcolor=self.ACCENT,
            highlightbackground=self.ENTRY_BORDER,
        )
        self.password_entry.pack(side="left", fill="x", expand=True)

        # Toggle visibility button
        self._pw_visible = False
        self.toggle_btn = tk.Button(
            row, text="👁", font=("Segoe UI", 12),
            bg=self.BG_SECONDARY, fg=self.FG_MUTED,
            relief="flat", cursor="hand2", bd=0,
            command=self._toggle_password,
        )
        self.toggle_btn.pack(side="left", padx=(6, 0))

    def _build_action_buttons(self) -> None:
        """
        Build the main action-button row:
        Encrypt | Decrypt | Clear | Exit
        """
        card = tk.Frame(self.root, bg=self.BG_SECONDARY, bd=0,
                        highlightbackground=self.CARD_SHADOW,
                        highlightthickness=1)
        card.pack(fill="x", padx=24, pady=8)

        inner = tk.Frame(card, bg=self.BG_SECONDARY)
        inner.pack(padx=16, pady=16)

        # Section label
        tk.Label(
            inner, text="⚡  Actions", font=self.FONT_LABEL,
            bg=self.BG_SECONDARY, fg=self.ACCENT, anchor="w",
        ).pack(fill="x", pady=(0, 10))

        btn_row = tk.Frame(inner, bg=self.BG_SECONDARY)
        btn_row.pack()

        buttons = [
            ("🔒  Encrypt", self.BTN_ENCRYPT, "#388E3C", self._on_encrypt),
            ("🔓  Decrypt", self.BTN_DECRYPT, "#EF6C00", self._on_decrypt),
            ("🗑  Clear",    self.BTN_CLEAR,   "#607D8B", self.clear_fields),
            ("✖  Exit",     self.BTN_EXIT,    "#D32F2F", self._on_exit),
        ]

        for text, bg, active_bg, cmd in buttons:
            btn = tk.Button(
                btn_row, text=text, font=self.FONT_BUTTON,
                bg=bg, fg=self.BTN_FG,
                activebackground=active_bg, activeforeground=self.BTN_FG,
                relief="flat", cursor="hand2",
                width=12, pady=6,
                command=cmd,
            )
            btn.pack(side="left", padx=6)

    def _build_status_bar(self) -> None:
        """Build the bottom status bar with helpful information."""
        status_frame = tk.Frame(self.root, bg=self.BG_PRIMARY)
        status_frame.pack(fill="x", side="bottom", padx=24, pady=(4, 12))

        self.status_var = tk.StringVar(value="Ready  •  Select a file to begin")
        tk.Label(
            status_frame, textvariable=self.status_var,
            font=self.FONT_STATUS, bg=self.BG_PRIMARY, fg=self.FG_MUTED,
            anchor="w",
        ).pack(fill="x")

        # Separator line
        sep = tk.Frame(self.root, bg=self.ENTRY_BORDER, height=1)
        sep.pack(fill="x", side="bottom", padx=24)

        # Security note
        note_frame = tk.Frame(self.root, bg=self.BG_PRIMARY)
        note_frame.pack(fill="x", side="bottom", padx=24, pady=(16, 0))

        tk.Label(
            note_frame,
            text="🛡  AES-256-CBC  •  PBKDF2-HMAC-SHA256 (600 000 iterations)  •  Random salt & IV",
            font=("Segoe UI", 8),
            bg=self.BG_PRIMARY,
            fg="#90A4AE",
            anchor="center",
        ).pack()

    # ────────────────────────────────────────────────────────────────────
    #  EVENT HANDLERS
    # ────────────────────────────────────────────────────────────────────

    def select_file(self) -> None:
        """
        Open a file-dialog so the user can pick a file from the
        filesystem.  Updates the file-path entry and status bar.
        """
        path = filedialog.askopenfilename(
            title="Select a File",
            filetypes=[
                ("All Files", "*.*"),
                ("Encrypted Files", "*.enc"),
                ("Text Files", "*.txt"),
                ("Documents", "*.pdf;*.docx;*.xlsx"),
                ("Images", "*.png;*.jpg;*.jpeg;*.gif;*.bmp"),
            ],
        )
        if path:
            self.selected_file = path
            self.file_var.set(path)
            filename = os.path.basename(path)
            size_kb = os.path.getsize(path) / 1024
            self.status_var.set(
                f"Selected: {filename}  ({size_kb:,.1f} KB)"
            )

    def _toggle_password(self) -> None:
        """Toggle password field between masked (●) and plain text."""
        self._pw_visible = not self._pw_visible
        self.password_entry.config(show="" if self._pw_visible else "●")
        self.toggle_btn.config(text="🔒" if self._pw_visible else "👁")

    def clear_fields(self) -> None:
        """Reset all fields and the status bar to their defaults."""
        self.selected_file = ""
        self.file_var.set("No file selected")
        self.password_var.set("")
        self._pw_visible = False
        self.password_entry.config(show="●")
        self.toggle_btn.config(text="👁")
        self.status_var.set("Ready  •  Select a file to begin")

    # ── Encrypt handler ─────────────────────────────────────────────────

    def _on_encrypt(self) -> None:
        """
        Validate inputs, encrypt the selected file, and display a
        success / error message box.
        """
        # Input validation
        if not self.selected_file:
            messagebox.showwarning("No File Selected",
                                   "Please select a file first.")
            return
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("No Password",
                                   "Please enter a password.")
            return
        if len(password) < 4:
            messagebox.showwarning("Weak Password",
                                   "Password must be at least 4 characters.")
            return

        # Confirm action
        if not messagebox.askyesno(
            "Confirm Encryption",
            f"Encrypt the file?\n\n{os.path.basename(self.selected_file)}",
        ):
            return

        self.status_var.set("Encrypting… please wait")
        self.root.update_idletasks()

        try:
            enc_path = encrypt_file(self.selected_file, password)
            size_kb = os.path.getsize(enc_path) / 1024
            self.status_var.set(
                f"Encrypted successfully  •  {os.path.basename(enc_path)}  "
                f"({size_kb:,.1f} KB)"
            )
            messagebox.showinfo(
                "Encryption Successful",
                f"File encrypted and saved as:\n\n{enc_path}",
            )
        except Exception as e:
            self.status_var.set("Encryption failed")
            messagebox.showerror("Encryption Error", str(e))

    # ── Decrypt handler ─────────────────────────────────────────────────

    def _on_decrypt(self) -> None:
        """
        Validate inputs, decrypt the selected *.enc* file, and display
        a success / error message box.
        """
        # Input validation
        if not self.selected_file:
            messagebox.showwarning("No File Selected",
                                   "Please select an encrypted (.enc) file.")
            return
        if not self.selected_file.endswith(".enc"):
            messagebox.showwarning(
                "Invalid File",
                "Please select a file with the .enc extension.",
            )
            return
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("No Password",
                                   "Please enter the decryption password.")
            return

        # Confirm action
        if not messagebox.askyesno(
            "Confirm Decryption",
            f"Decrypt the file?\n\n{os.path.basename(self.selected_file)}",
        ):
            return

        self.status_var.set("Decrypting… please wait")
        self.root.update_idletasks()

        try:
            dec_path = decrypt_file(self.selected_file, password)
            size_kb = os.path.getsize(dec_path) / 1024
            self.status_var.set(
                f"Decrypted successfully  •  {os.path.basename(dec_path)}  "
                f"({size_kb:,.1f} KB)"
            )
            messagebox.showinfo(
                "Decryption Successful",
                f"File decrypted and restored as:\n\n{dec_path}",
            )
        except ValueError as e:
            self.status_var.set("Decryption failed – wrong password?")
            messagebox.showerror("Decryption Error", str(e))
        except Exception as e:
            self.status_var.set("Decryption failed")
            messagebox.showerror("Decryption Error", str(e))

    # ── Exit handler ────────────────────────────────────────────────────

    def _on_exit(self) -> None:
        """Ask the user for confirmation before closing the app."""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.root.destroy()


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
