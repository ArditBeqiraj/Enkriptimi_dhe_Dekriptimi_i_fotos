import os
import json
import hashlib
import numpy as np
from PIL import Image, ExifTags, ImageOps
from tkinter import Tk, Button, filedialog, messagebox

class UniversalBinaryConverter:
    def __init__(self, master):
        self.master = master
        master.title("Universal Binary Converter Pro")
        master.geometry("500x200")

        Button(master, text="Foto → Bin", command=self.image_to_binary, height=2, width=20).pack(pady=5)
        Button(master, text="Bin → Foto", command=self.binary_to_image, height=2, width=20).pack(pady=5)
        Button(master, text="Vizualizo Bin", command=self.visualize_binary, height=2, width=20).pack(pady=5)

    def image_to_binary(self):
        file_path = filedialog.askopenfilename(filetypes=[("Images", "*.jpg *.jpeg *.png *.bmp")])
        if not file_path:
            return

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                checksum = hashlib.sha256(file_data).hexdigest()

            img = Image.open(file_path)
            exif_data = self._get_exif_data(img)


            metadata = {
                "checksum": checksum,
                "file_size": os.path.getsize(file_path),
                "mime_type": Image.MIME.get(img.format, "application/octet-stream"),
                "original_format": img.format,
                "image_width": img.width,
                "image_height": img.height,
                "image_size": f"{img.width}x{img.height}",
            }

            output_path = os.path.splitext(file_path)[0] + ".ubf"
            with open(output_path, 'wb') as f:
                meta_json = json.dumps(metadata, indent=2)
                f.write(meta_json.encode('utf-8').ljust(4096, b'\0'))
                f.write(np.array(img).tobytes())

            messagebox.showinfo("Sukses", f"Foto u ruajt si:\n{output_path}\nMetadata: {len(metadata)} fusha")
        except Exception as e:
            messagebox.showerror("Gabim", f"Konvertimi dështoi: {str(e)}")

    def binary_to_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Binary Files", "*.ubf")])
        if not file_path:
            return

        try:
            with open(file_path, 'rb') as f:
                meta_json = f.read(4096).split(b'\0')[0].decode('utf-8')
                metadata = json.loads(meta_json)
                img_array = np.frombuffer(f.read(), dtype=np.uint8)


                channels = 3 if metadata["mime_type"] in ["image/jpeg", "image/png"] else 1
                img_array = img_array.reshape((metadata["image_height"], metadata["image_width"], channels)) if channels > 1 else img_array.reshape((metadata["image_height"], metadata["image_width"]))

                img = Image.fromarray(img_array)
                ext = metadata.get("mime_type", "image/png").split('/')[-1]
                output_path = os.path.splitext(file_path)[0] + f"_restored.{ext}"
                img.save(output_path, format=metadata.get("original_format", "PNG"))
                img.show()
                messagebox.showinfo("Sukses", f"Foto e rikthyer")
        except Exception as e:
            messagebox.showerror("Gabim", f"Rikthimi dështoi: {str(e)}")

    def _get_exif_data(self, img):
        exif = {}
        try:
            for tag, value in img.getexif().items():
                if tag in ExifTags.TAGS:
                    exif[ExifTags.TAGS[tag]] = value
        except Exception:
            pass
        return exif

    def visualize_binary(self):
        file_path = filedialog.askopenfilename(filetypes=[("Binary Files", "*.ubf *.bin")])
        if not file_path:
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()


                has_metadata = False
                if len(data) >= 4096:
                    try:
                        meta = json.loads(data[:4096].split(b'\0')[0].decode('utf-8'))
                        if 'image_width' in meta and 'image_height' in meta:
                            has_metadata = True
                    except:
                        pass

                if has_metadata:

                    arr = np.frombuffer(data[4096:], dtype=np.uint8)
                    w = meta['image_width']
                    h = meta['image_height']
                    channels = meta.get('channels', 3)
                else:

                    arr = np.frombuffer(data, dtype=np.uint8)
                    size = int(np.sqrt(len(arr) // 3))
                    w = h = size
                    channels = 3

                arr = arr[:w * h * channels]

                if channels == 3:
                    img = Image.fromarray(arr.reshape(h, w, 3))
                elif channels == 1:
                    img = Image.fromarray(arr.reshape(h, w), 'L')
                else:
                    raise ValueError("Kanale të panjohura")

                img = ImageOps.autocontrast(img)
                img.show()

        except Exception as e:
            messagebox.showerror("Gabim", f"Vizualizimi dështoi: {str(e)}")

if __name__ == "__main__":
    root = Tk()
    app = UniversalBinaryConverter(root)
    root.mainloop()

