import os
import cv2
import json
import base64
import numpy as np
from tkinter import *
from PIL import Image, ImageTk
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from tkinter import filedialog, messagebox


class AESImageEncryptor:
    def __init__(self, master):
        self.master = master
        master.title("AES Image Encryptor")
        master.geometry("600x500")

        self.mode = StringVar(value="encrypt")
        Label(master, text="AES Image Encryption/Decryption", font=('Arial', 14)).pack(pady=10)

        Frame(master).pack(pady=5)
        Radiobutton(master, text="Encrypt Image", variable=self.mode, value="encrypt").pack()
        Radiobutton(master, text="Decrypt .bin File", variable=self.mode, value="decrypt").pack()

        self.image_label = Label(master)
        self.image_label.pack(pady=10)

        frame = Frame(master)
        frame.pack(pady=10)
        Label(frame, text="AES Key (16/24/32 bytes):").grid(row=0, column=0)
        self.key_entry = Entry(frame, width=40)
        self.key_entry.grid(row=0, column=1)
        Button(frame, text="Generate Key", command=self.generate_key).grid(row=0, column=2, padx=5)

        Button(master, text="Select File", command=self.select_file).pack(pady=10)
        Button(master, text="Process", command=self.process_file).pack(pady=10)

        self.file_path = None
        self.generate_key()

    def generate_key(self):
        key = get_random_bytes(32)
        self.key_entry.delete(0, 'end')
        self.key_entry.insert(0, base64.b64encode(key).decode())

    def select_file(self):
        if self.mode.get() == "encrypt":
            self.file_path = filedialog.askopenfilename(
                title="Select Image to Encrypt",
                filetypes=[("Image Files", "*.jpg *.jpeg *.png")]
            )
        else:
            self.file_path = filedialog.askopenfilename(
                title="Select .bin File to Decrypt",
                filetypes=[("Encrypted Files", "*.bin")]
            )

        if self.file_path:
            if self.mode.get() == "encrypt":
                self.display_image(self.file_path)
            else:
                Label(self.master, text=f"Selected: {os.path.basename(self.file_path)}").pack()

    def display_image(self, path):
        try:
            img = Image.open(path)
            img.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(img)
            self.image_label.config(image=photo)
            self.image_label.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Cannot display image: {str(e)}")

    def process_file(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "Please select a file first!")
            return

        try:
            key = base64.b64decode(self.key_entry.get())
            if len(key) not in [16, 24, 32]:
                raise ValueError("Key must be 16, 24 or 32 bytes long")

            if self.mode.get() == "encrypt":
                self.encrypt_image(key)
            else:
                self.decrypt_image(key)

        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")

    def encrypt_image(self, key):
        img = cv2.imread(self.file_path)
        if img is None:
            raise ValueError("Could not read image")

        height, width, channels = img.shape
        img_bytes = img.tobytes()

        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(img_bytes, AES.block_size))

        metadata = {
            "original_filename": os.path.basename(self.file_path),
            "image_width": width,
            "image_height": height,
            "channels": channels
        }
        meta_json = json.dumps(metadata).encode("utf-8")
        meta_block = meta_json.ljust(4096, b'\0')

        save_path = os.path.splitext(self.file_path)[0] + "_encrypted.bin"
        with open(save_path, 'wb') as f:
            f.write(meta_block)
            f.write(iv)
            f.write(encrypted)

        messagebox.showinfo("Success",
                            f"Image encrypted with metadata!\n\n"
                            f"Saved to: {save_path}\n"
                            f"Key: {base64.b64encode(key).decode()}")

    def decrypt_image(self, key):

        with open(self.file_path, 'rb') as f:
            meta_block = f.read(4096)
            metadata = json.loads(meta_block.split(b'\0')[0].decode('utf-8'))
            iv = f.read(16)
            encrypted_data = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        img_array = np.frombuffer(decrypted, dtype=np.uint8).reshape(
            (metadata["image_height"], metadata["image_width"], metadata["channels"])
        )

        save_path = os.path.splitext(self.file_path)[0] + "_decrypted.png"
        cv2.imwrite(save_path, img_array)
        messagebox.showinfo("Success", f"Image decrypted and saved to:\n{save_path}")
        self.display_image(save_path)


if __name__ == "__main__":
    root = Tk()
    app = AESImageEncryptor(root)
    root.mainloop()
