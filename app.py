from flask import Flask
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Sự kiện: Xác minh chữ ký từ frontend gửi qua socket
@socketio.on('verify_signature')
def handle_verify_signature(data):
    message = data.get('message', '').encode()
    signature_str = data.get('signature', '')
    public_key_str = data.get('public_key', '')

    try:
        # Giải mã khóa công khai từ PEM
        public_key = serialization.load_pem_public_key(public_key_str.encode())

        # Giải mã chữ ký (base64 hoặc raw)
        try:
            signature = base64.b64decode(signature_str)
        except Exception:
            signature = signature_str.encode()

        # Xác minh
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        emit('verify_result', {'verified': True})
    except Exception as e:
        emit('verify_result', {'verified': False, 'error': str(e)})

# Khởi chạy server tại cổng 5050 (tránh trùng cổng 5000)
if __name__ == '__main__':
    socketio.run(app, debug=True, port=5010)
