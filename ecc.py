from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_ecc_keys():

    print("--- Task 2A: Generating ECC Keys ---")

    private_key = ec.generate_private_key(ec.SECP256R1())
    print("Private key generated successfully.")

    public_key = private_key.public_key()
    print("Public key derived successfully.")


    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("ecc_private_key.pem", "wb") as f:
        f.write(pem_private)
    print("Private key saved to ecc_private_key.pem")

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("ecc_public_key.pem", "wb") as f:
        f.write(pem_public)
    print("Public key saved to ecc_public_key.pem")
    print("-" * 35 + "\n")


def sign_and_verify_message():

    print("--- Task 2B: Signing and Verifying Message ---")

    message = b"Elliptic Curves are efficient."
    with open("ecc.txt", "wb") as f:
        f.write(message)
    print(f"Message to sign: '{message.decode()}'")

    try:
        with open("ecc_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
    except FileNotFoundError:
        print("Error: Private key file not found. Please run key generation first.")
        return


    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print(f"Signature (in hex): {signature.hex()}")

    with open("message.sig", "wb") as f:
        f.write(signature)
    print("Signature saved to message.sig")

    try:
        with open("ecc_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("Error: Public key file not found. Please run key generation first.")
        return


    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print("\nVerification successful: The signature is valid.")
    except InvalidSignature:
        print("\nVerification failed: The signature is NOT valid.")
    except Exception as e:
        print(f"An unexpected error occurred during verification: {e}")
    print("-" * 35)


if __name__ == "__main__":
    generate_ecc_keys()
    sign_and_verify_message()