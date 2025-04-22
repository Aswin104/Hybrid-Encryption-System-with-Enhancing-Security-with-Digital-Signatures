🔐 Hybrid Encryption System with Enhanced Security using Digital Signatures
This project implements a secure communication mechanism combining RSA, AES, and Digital Signatures to ensure confidentiality, integrity, and authentication of messages. It uses a hybrid encryption approach, encrypting data with AES (symmetric encryption) and securing the AES key with RSA (asymmetric encryption), along with digital signing for validation.

✨ Features
✅ Hybrid Encryption: AES for fast, secure message encryption; RSA for secure AES key exchange.

✅ Digital Signatures: Ensures message authenticity and integrity.

✅ Key Management: Auto-generates and stores RSA key pairs for sender and receiver.

✅ Interactive CLI: Simple command-line interface for encryption/signing and decryption/verification.

📂 Directory Structure
perl
Copy
Edit
.
├── keys/
│   ├── sender_private.pem
│   ├── sender_public.pem
│   ├── receiver_private.pem
│   └── receiver_public.pem
├── Code2.py
└── README.md
🔧 Requirements
Python 3.x

pycryptodome library

Install dependencies with:

bash
Copy
Edit
pip install pycryptodome
🚀 How to Use
Run the script:

bash
Copy
Edit
python Code2.py
Option 1: Encrypt & Sign
Enter your message.

The script will:

Generate a random AES key

Encrypt the message using AES

Encrypt the AES key using RSA

Sign the encrypted message using the sender’s private key

It will display:

Encrypted AES key

Encrypted message

Digital signature

Option 2: Decrypt & Verify
Provide the:

Encrypted AES key

Encrypted message

Digital signature

The script will:

Verify the signature using the sender's public key

Decrypt the AES key using the receiver’s private key

Decrypt the message using AES

🔐 Security Architecture
RSA (2048 bits): For public-key encryption of the AES key.

AES (128-bit, CBC mode): For encrypting message data.

SHA-256 + PKCS#1 v1.5: For digital signing and signature verification.

📜 License
This project is licensed under the MIT License.

👨‍💻 Author
Aswin Kumar Gamango
Feel free to fork and enhance this project for your own security needs!

