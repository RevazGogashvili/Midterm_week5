This file describes the process and commands used for this midterm.

Task 1: AES Encryption 

1. Create `secret.txt' file using OpenSSL:
   Command:
   echo "This file contains top secret information." > secret.txt
2. Encrypt secret.txt using OpenSSL:
   Command:
   openssl enc -e -aes-128-cbc -in secret.txt -out secret.enc
   Terminal Interaction during encryption:
   enter aes-128-cbc encryption password:
   Verifying - enter aes-128-cbc encryption password:
 3. Decryption:
    Command:
    openssl enc -d -aes-128-cbc -in secret.enc -out decrypted_secret.txt
    Terminal Interaction during decryption:
    enter aes-128-cbc decryption password:
5. Verify Decryption Success:
   Command/Output: 
   sha256sum secret.txt decrypted_secret.txt
163dbe3718f40a2e1fdf75cf3115ce519312a400286839c2c5bb45256c34445c *secret.txt
163dbe3718f40a2e1fdf75cf3115ce519312a400286839c2c5bb45256c34445c *decrypted_secret.txt


Task 2: ECC Signature Verification

This task uses Python's `cryptography` library to perform Elliptic Curve Cryptography operations.

### Task 2A: Generate ECC Keys

ECC keys were generated using the `prime256v1` (SECP256R1) curve. The private and public keys were saved to `ecc_private_key.pem` and `ecc_public_key.pem` respectively.

### Task 2B: Sign and Verify a Message

A message was created in `ecc.txt`. This message was then signed using the private key, and the resulting signature was verified using the public key.

#### Python Script (`task2_ecc.py`)

The following script was used to perform all operations for Task 2:

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
      
Running the script gives the following output:

       python ecc.py
      --- Task 2A: Generating ECC Keys ---
      Private key generated successfully.
      Public key derived successfully.
      Private key saved to ecc_private_key.pem
      Public key saved to ecc_public_key.pem
      -----------------------------------

      --- Task 2B: Signing and Verifying Message ---
      Message to sign: 'Elliptic Curves are efficient.'
      Signature (in hex): 3045022100d4be5623818f41be3be755cfb173b9f6b6abd81ad0c349f010474a7dc1d562c202205d919dec080ce1e96bd699597ebe701e4ba388015f31b62dbbc70c1082ba3866
      Signature saved to message.sig
      
      Verification successful: The signature is valid.

Task 3: Hashing & HMAC

