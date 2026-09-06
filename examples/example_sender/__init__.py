from importlib import resources

from cryptography.hazmat.primitives.serialization import pkcs12

resource = resources.files("tests.assets.test_credentials.test_sender")
keystore_p12 = resource / "key_store.p12"

TEST_KEYSTORE_PASS = b"abc"
keystore_bytes = keystore_p12.open("rb").read()
private_key, certificate, _ = pkcs12.load_key_and_certificates(keystore_bytes, TEST_KEYSTORE_PASS)
