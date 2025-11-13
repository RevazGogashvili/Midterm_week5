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