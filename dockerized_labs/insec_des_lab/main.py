from flask import Flask, render_template, request, make_response
import pickle
import base64
import json
from dataclasses import dataclass

app = Flask(__name__)

@dataclass
class User:
    username: str 
    is_admin: bool = False

    def __reduce__(self):
        # Intentionally vulnerable __reduce__ method to match PyGoat
        return (User, (self.username, self.is_admin))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Match PyGoat's serialization format
    serialized = base64.b64encode(pickle.dumps(user)).decode()
    return render_template('result.html', serialized=serialized)

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    try:
        serialized_data = request.form.get('serialized_data', '')
        decoded_data = base64.b64decode(serialized_data)

        # CWE-502 (Deserialización insegura) - Solución: Evitar la deserialización de datos no confiables mediante pickle
        # Usar JSON como formato de serialización seguro y validar la estructura esperada.
        if isinstance(decoded_data, (bytes, bytearray)):
            decoded_text = decoded_data.decode("utf-8", errors="strict")
        else:
            decoded_text = str(decoded_data)

        user = json.loads(decoded_text)
        if not isinstance(user, dict):
            return "Invalid token format", 400

        allowed_keys = {"username", "role"}
        if not set(user.keys()).issubset(allowed_keys):
            return "Invalid token content", 400

        if isinstance(user, User):
            if user.is_admin:
                message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
            else:
                message = f"Welcome {user.username}. Only admins can see the secret content."
        else:
            message = "Invalid user data"
        
        return render_template('result.html', message=message)
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

    