

from flask import Flask, render_template, request, jsonify
import rsa

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


# Generate a  key pair
@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.get_json(silent=True) or {}
    try:
        try:
              bits = int(data.get("bits"))
        except (TypeError, ValueError):
            raise ValueError("Prime size must be a whole number")
        keys = rsa.generate_keys(bits)
        return jsonify(ok=True, keys={k: str(v) for k, v in keys.items()})
    except ValueError as err:
        return jsonify(ok=False, error=str(err)), 400


# Encrypt text with a public key "e,n"
@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json(silent=True) or {}
    try:
        text = data.get("text", "")
        e, n = rsa.parse_key(data.get("key", ""))
        return jsonify(ok=True, result=rsa.encrypt_text(text, e, n))
    except ValueError as err:
        return jsonify(ok=False, error=str(err)), 400


# Decrypt ciphertext with a private key "d,n"
@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = request.get_json(silent=True) or {}
    try:
        cipher = data.get("text", "")
        d, n = rsa.parse_key(data.get("key", ""))
        return jsonify(ok=True, result=rsa.decrypt_text(cipher, d, n))
    except ValueError as err:
        return jsonify(ok=False, error=str(err)), 400


if __name__ == "__main__":
    app.run(debug=True)