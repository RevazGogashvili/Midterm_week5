This file describes the process and commands used for task1: AES Encryption 

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
