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