from flask import Flask, render_template, request, send_from_directory, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
KEY_FOLDER = "keys"
SIGNATURE_FOLDER = "signatures"
MERGED_FOLDER = "merged"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)
os.makedirs(SIGNATURE_FOLDER, exist_ok=True)
os.makedirs(MERGED_FOLDER, exist_ok=True)



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(os.path.join(KEY_FOLDER, "private.pem"), "wb") as f:
        f.write(private_pem)
    with open(os.path.join(KEY_FOLDER, "public.pem"), "wb") as f:
        f.write(public_pem)

    return jsonify({"message": "✨ Tạo khóa thành công!", "private": "private.pem", "public": "public.pem"})

@app.route("/download_key/<key_type>")
def download_key(key_type):
    filename = "private.pem" if key_type == "private" else "public.pem"
    return send_from_directory(KEY_FOLDER, filename, as_attachment=True)

@app.route("/sign_file", methods=["POST"])
def sign_file():
    file = request.files["file"]
    filename = file.filename
    data = file.read()

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    with open(filepath, "wb") as f:
        f.write(data)

    private_key = serialization.load_pem_private_key(
        open(os.path.join(KEY_FOLDER, "private.pem"), "rb").read(),
        password=None
    )

    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    sig_path = os.path.join(SIGNATURE_FOLDER, filename + ".sig")
    with open(sig_path, "wb") as f:
        f.write(signature)

    return jsonify({
        "message": "✅ Đã tạo chữ ký số!",
        "signature": filename + ".sig"
    })

@app.route("/embed_signature", methods=["POST"])
def embed_signature():
    file = request.files["file"]
    sig = request.files["signature"]

    filename = file.filename
    data = file.read()
    signature = sig.read()

    merged_path = os.path.join(MERGED_FOLDER, filename + ".signed")
    with open(merged_path, "wb") as f:
        f.write(data + b"\n---SIGNATURE---\n" + signature)

    return jsonify({"message": "✅ Chèn chữ ký thành công!", "merged_file": filename + ".signed"})

@app.route("/verify", methods=["POST"])
def verify():
    file = request.files["file"]
    sig = request.files["signature"]
    pubkey = request.files.get("pubkey")

    data = file.read()
    signature = sig.read()

    if pubkey:
        public_key = serialization.load_pem_public_key(pubkey.read())
    else:
        public_key = serialization.load_pem_public_key(
            open(os.path.join(KEY_FOLDER, "public.pem"), "rb").read()
        )

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return jsonify({"valid": True, "message": "✅ Chữ ký hợp lệ!"})
    except Exception:
        return jsonify({"valid": False, "message": "❌ Chữ ký không hợp lệ!"})

@app.route("/download/<folder>/<filename>")
def download(folder, filename):
    folder_path = {
        "signature": SIGNATURE_FOLDER,
        "merged": MERGED_FOLDER,
        "key": KEY_FOLDER
    }.get(folder, UPLOAD_FOLDER)
    return send_from_directory(folder_path, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
