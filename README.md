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

             --- Generating ECC Keys ---
      Private key generated successfully.
      Public key derived successfully.
      Private key saved to ecc_private_key.pem
      Public key saved to ecc_public_key.pem
      -----------------------------------
      
      --- Signing and Verifying Message ---
      Message to sign: 'Elliptic Curves are efficient.'
      Signature (in hex): 304402202556237b56dfd09f243774230dddd23682a13089ce2f64af3d008be49e08fa80022015acf56762b7c196ab21d4b1daf6000b37b8dcb246d397c8216ad79baf0f4610
      Signature saved to message.sig
      
      Verification successful: The signature is valid.
      -----------------------------------
      
      Process finished with exit code 0

Task 3: Hashing & HMAC

This task demonstrates hashing for data integrity and HMAC for authenticated data integrity using Python. All operations were performed using the `task3_hashing.py` script.

The following script was used to perform all operations for task 3:

      import hashlib
      import hmac
      
      
      def task_3a_sha256_hash():
      
          print("--- SHA-256 Hash ---")
      
      
          message = b"Never trust, always verify."
          with open("data.txt", "wb") as f:
              f.write(message)
          print(f"Created data.txt with content: '{message.decode()}'")
      
          sha256_hash = hashlib.sha256()
      
          with open("data.txt", "rb") as f:
              # Read the file in chunks in case it's large
              for chunk in iter(lambda: f.read(4096), b""):
                  sha256_hash.update(chunk)
      
          hex_digest = sha256_hash.hexdigest()
          print(f"SHA-256 Hash: {hex_digest}")
          print("-" * 35 + "\n")
          return hex_digest
      
      
      def task_3b_hmac_sha256():
      
          print("--- HMAC-SHA256 ---")
      
          key = b"secretkey123"
      
          with open("data.txt", "rb") as f:
              message = f.read()
      
          hmac_digest = hmac.new(key, message, hashlib.sha256).hexdigest()
      
          print(f"Using key: '{key.decode()}'")
          print(f"HMAC-SHA256: {hmac_digest}")
          print("-" * 35 + "\n")
          return hmac_digest
      
      
      def task_3c_integrity_check(original_hmac):
      
          print("--- Integrity Check ---")
      
          modified_message = b"Never trust, always verifx."  # 'y' changed to 'x'
          with open("data_modified.txt", "wb") as f:
              f.write(modified_message)
          print(f"Created data_modified.txt with content: '{modified_message.decode()}'")
      
          key = b"secretkey123"
      
          hmac_digest_modified = hmac.new(key, modified_message, hashlib.sha256).hexdigest()
      
          print("\n--- Comparison ---")
          print(f"Original HMAC: {original_hmac}")
          print(f"New HMAC:      {hmac_digest_modified}")
      
          print("\n--- Explanation ---")
          if original_hmac != hmac_digest_modified:
              print("Result: The HMACs DO NOT match.")
              print("Why HMAC is important:")
              print("1. Integrity: The fact that the HMAC changed proves that the original message was altered. "
                    "Even a one-character change results in a completely different HMAC.")
              print("2. Authenticity: Because generating the correct HMAC requires the secret key, a valid HMAC "
                    "verifies that the message was created by a party who possesses the key. Our check would "
                    "successfully detect an unauthorized modification.")
          else:
              print("Result: The HMACs match, which should not have happened. Check the code.")
          print("-" * 35)
      
      
      if __name__ == "__main__":
          task_3a_sha256_hash()
          original_hmac_value = task_3b_hmac_sha256()
          task_3c_integrity_check(original_hmac_value)

Running the script gives following the output:

       python hashing.py
      --- SHA-256 Hash ---
      Created data.txt with content: 'Never trust, always verify.'
      SHA-256 Hash: 50dddf8b540a8d16693d741462e1f0431fe43acd4f9c2d006edf7d2e828f7fa4
      -----------------------------------
      
      --- HMAC-SHA256 ---
      Using key: 'secretkey123'
      HMAC-SHA256: 77ff6d313b1afbac12ceb402d89d5f5dac37faebe581527cff8dc04eb3193df2
      -----------------------------------
      
      --- Integrity Check ---
      Created data_modified.txt with content: 'Never trust, always verifx.'
      
      --- Comparison ---
      Original HMAC: 77ff6d313b1afbac12ceb402d89d5f5dac37faebe581527cff8dc04eb3193df2
      New HMAC:      8a27d6a484a2f4c4c163af74d28b82cc2067b240f9fc9245237f0f835d418021
      
      --- Explanation ---
      Result: The HMACs DO NOT match.
      Why HMAC is important:
      1. Integrity: The fact that the HMAC changed proves that the original message was altered. Even a one-character change results in a completely different HMAC.
      2. Authenticity: Because generating the correct HMAC requires the secret key, a valid HMAC verifies that the message was created by a party who possesses the key. Our check would successfully detect an unauthorized modification.
      -----------------------------------


Task 4 

Diffie-Hellman (DH) is a foundational protocol for establishing secure communications over an untrusted network, like the internet. Its primary use is to allow two parties, who have no prior knowledge of each other, to jointly establish a shared secret key. This key can then be used for symmetric encryption (like AES) to secure their conversation. In practice, DH is a critical component of the TLS handshake, the process that secures HTTPS connections. When your browser shows a padlock icon, a DH exchange (or its elliptic curve variant, ECDH) has likely occurred to create a unique, temporary session key for encrypting all the traffic between you and the server. It is also central to secure messaging applications like Signal and WhatsApp, where it's used to establish end-to-end encrypted sessions between users, ensuring that only the participants can read the messages.

The protocol's importance lies in its ability to provide Forward Secrecy. Because the shared session keys are generated on-the-fly and discarded after the session, the compromise of a server's long-term private key does not compromise past encrypted communications. An attacker with a server's stolen key cannot go back and decrypt previously recorded traffic, making DH essential for robust, long-term communication privacy.

In this case I simulated a DH between Alice and Bob, where the following script was used:

      from cryptography.hazmat.primitives.asymmetric import dh
      from cryptography.hazmat.primitives import serialization
      
      
      def simulate_diffie_hellman():
      
          print("--- Diffie-Hellman Key Exchange Simulation ---")
      
          parameters = dh.generate_parameters(generator=2, key_size=2048)
      
          print("\n--- Alice's Actions ---")
      
          alice_private_key = parameters.generate_private_key()
          print("Alice has generated her private key.")
      
          alice_public_key = alice_private_key.public_key()
          print("Alice computes her public key from her private key.")
      
          alice_public_pem = alice_public_key.public_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo
          )
          print("\nAlice’s Public Key (to be sent to Bob):")
          print(alice_public_pem.decode())
      
          print("\n--- Bob's Actions ---")
      
          bob_private_key = parameters.generate_private_key()
          print("Bob has generated his private key.")
      
          bob_public_key = bob_private_key.public_key()
          print("Bob computes his public key from his private key.")
      
          bob_public_pem = bob_public_key.public_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo
          )
          print("\nBob’s Public Key (to be sent to Alice):")
          print(bob_public_pem.decode())
      
          alice_shared_key = alice_private_key.exchange(bob_public_key)
          print("\nAlice has derived the shared secret.")
      
          bob_shared_key = bob_private_key.exchange(alice_public_key)
          print("Bob has derived the shared secret.")
      
          print("\n--- Verification ---")
          print("Shared Secret (Alice's side):", alice_shared_key.hex())
          print("Shared Secret (Bob's side):  ", bob_shared_key.hex())
      
          if alice_shared_key == bob_shared_key:
              print("\nSuccess! Both Alice and Bob have derived the exact same secret key.")
          else:
              print("\nFailure! The keys do not match.")
          print("-" * 35)
      
      
      if __name__ == "__main__":
          simulate_diffie_hellman()


Running the script gave the following output:

       python Diffie-Hellman.py
      --- Diffie-Hellman Key Exchange Simulation ---
      
      --- Alice's Actions ---
      Alice has generated her private key.
      Alice computes her public key from her private key.
      
      Alice’s Public Key (to be sent to Bob):
      -----BEGIN PUBLIC KEY-----
      MIICJDCCARcGCSqGSIb3DQEDATCCAQgCggEBAL+fyGrMfE7FsxNdpWLQDQjzICj+
      0G6KCZYJcvfeuCJo99xk67s440trOK4ZxMYZ6+AxTBBjolV/7Vt3hFgb/NbkMsQP
      3VMrbWWE2EdFziJpQBNNFQo/ApepGORTx2RnqaIXc+VvyrAUfALdxTK9G5R2LJIr
      37d8ygUV8YqZCHlnHsiCIeWoLbRdfIe6CShPmCAb7rqXQS8ibT6y7q/8pVS+0D2S
      Ajt9O4t5sBFpM2xHW3Zmkm5pFauY9yrfjxI5e1x8we4J5rGE0yAgGN0AG7hKeEkS
      JaxmUCBN6no1FJwmmLqnSb5jFzICyfhWQ5mcU6DIiWW03H8/Wx0s6hqZfEcCAQID
      ggEFAAKCAQAUx26RtHICrxh/tPDpIhTN0eSSuY046eGmWJr7de+hpmi/BGWRIzuT
      Let7aKFnMAv8C2+Q0EDKhtefPkZxNGueJA1gpj9dXblhbgUcupA5hFpULPk49GVG
      Jpmliz9Zubx1+o6XZ2dM9J4hgQ4Enyb27UmdPGprBuouy81Al+35920iI8H2TGr+
      HhldxHpGeQVCiPY8vhdc6uCtqNHm34sbAhpar9Af6TniCBA+tKs+q1KsbsOokCDo
      sk//b0v+VBJJzqRQtKO87lKrtL9bvWklatcIaRKEc/5BrKYkCB79bww/LKRm1f4C
      vdPd7jhMVbh3sal2ThHhyrF9RdAef2fY
      -----END PUBLIC KEY-----
      
      
      --- Bob's Actions ---
      Bob has generated his private key.
      Bob computes his public key from his private key.
      
      Bob’s Public Key (to be sent to Alice):
      -----BEGIN PUBLIC KEY-----
      MIICJTCCARcGCSqGSIb3DQEDATCCAQgCggEBAL+fyGrMfE7FsxNdpWLQDQjzICj+
      0G6KCZYJcvfeuCJo99xk67s440trOK4ZxMYZ6+AxTBBjolV/7Vt3hFgb/NbkMsQP
      3VMrbWWE2EdFziJpQBNNFQo/ApepGORTx2RnqaIXc+VvyrAUfALdxTK9G5R2LJIr
      37d8ygUV8YqZCHlnHsiCIeWoLbRdfIe6CShPmCAb7rqXQS8ibT6y7q/8pVS+0D2S
      Ajt9O4t5sBFpM2xHW3Zmkm5pFauY9yrfjxI5e1x8we4J5rGE0yAgGN0AG7hKeEkS
      JaxmUCBN6no1FJwmmLqnSb5jFzICyfhWQ5mcU6DIiWW03H8/Wx0s6hqZfEcCAQID
      ggEGAAKCAQEAgeqRQFzctVuBHJq5K3txwlrNxhBTvXoOwnobGNpUBzhTE9ANHnd2
      xPatpKqNC3F4NS2jNo3Y1Vgq0p+dhlqNXPu+i9lui3viEk6gBhHObRCwkAQ0B0AZ
      Ff0sl2Ktn6IZHLltCfIjucQXVfFRsf3OsK0jQlA+37PK7SMUsqFtdGk8hMX6xNqp
      14I2jtNNHIZC6PNoVU5xTnYlBmwG94wFQOr+LetZGY0/tOY+eujTCwpprMLNRyb8
      HL2ispOz8/wz/4fICTBMtPo6AjDCR/6bpDUZR85nHMUlRxSj2G88QsAPxs2hPXUJ
      1PPtYRsgFhrj0ZvC/7n8P4PKh6O4/K/OXg==
      -----END PUBLIC KEY-----
      
      
      Alice has derived the shared secret.
      Bob has derived the shared secret.
      
      --- Verification ---
      Shared Secret (Alice's side): 191f49a512e98663c65f5e47aa16714e4905dafc9c367dfa59e8a290e156c445a7198220242ac04b073edbcf18c2bc280d1957e7a5b6ccdcf2562703b3c3e61cc34f567239cc1fbde2e25e0cb4c7cc26042376adfce48c6cd0d0a1503649d820ef8d4b9bb86931713059cf11e19e52ee41f02f1bc21f7906a2996b4d34bfdc277ee3b71c3fbb7b2722eded7f9cebc695d3f55f128fbdcafd235dc60449ba7d339791c34e921d90343c8c5b1b86e1cbd0dd34bb77e18179189b08e846d9efd08731d62f8ec99912ac1e1fb54a9436342c098f378ff756ab7f18831ef2fa65fa73f8f11c6b6e7ae6fa17eb5c94bc2234d989a08cea4ee08ec3a7c525c2e79afcb4
      Shared Secret (Bob's side):   191f49a512e98663c65f5e47aa16714e4905dafc9c367dfa59e8a290e156c445a7198220242ac04b073edbcf18c2bc280d1957e7a5b6ccdcf2562703b3c3e61cc34f567239cc1fbde2e25e0cb4c7cc26042376adfce48c6cd0d0a1503649d820ef8d4b9bb86931713059cf11e19e52ee41f02f1bc21f7906a2996b4d34bfdc277ee3b71c3fbb7b2722eded7f9cebc695d3f55f128fbdcafd235dc60449ba7d339791c34e921d90343c8c5b1b86e1cbd0dd34bb77e18179189b08e846d9efd08731d62f8ec99912ac1e1fb54a9436342c098f378ff756ab7f18831ef2fa65fa73f8f11c6b6e7ae6fa17eb5c94bc2234d989a08cea4ee08ec3a7c525c2e79afcb4
      
      Success! Both Alice and Bob have derived the exact same secret key.
