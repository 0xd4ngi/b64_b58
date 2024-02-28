from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import base64 
import base58

encrypted_message_base64 = ""
private_key_base58 = ""
public_key_base58 = ""

def decrypt(encrypted_message_base64, private_key_base58, public_key_base58):
    encrypted_message =  base64.b64decode(encrypted_message_base64)
    private_key_bytes=base58.b58decode(private_key_base58)
    public_key_bytes=base58.b58decode(public_key_base58)

    private_key = x25519.load_private_key(private_key_bytes, backend=default_backend())
    public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

    shared_key = private_key.exchange(public_key)
    symmetric_key = shared_key[:32]

    decrypted_message = decrypt_message(encrypted_message, symmetric_key)

    return decrypted_message.decode('utf-8')



decrypted_message = x25519_decrypt(encrypted_message_base64, private_key_base58, public_key_base58)
print("Decrypted Message:", decrypted_message)