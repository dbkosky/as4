from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class CipherHandler:

    @classmethod
    def encrypt_payload(cls, payload: bytes) -> tuple[bytes, bytes]:
        session_key = AESGCM.generate_key(bit_length=128)
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        encrypted_blob = nonce + ciphertext
        return session_key, encrypted_blob

    @classmethod
    def decrypt_payload(cls, session_key: bytes, encrypted_blob: bytes):
        nonce, data = encrypted_blob[:12], encrypted_blob[12:]
        cipher = AESGCM(session_key)
        decrypted_payload = cipher.decrypt(nonce, data, None)
        return decrypted_payload
