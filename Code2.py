import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

KEY_DIR = "keys"
SENDER_PRIVATE_FILE = f"{KEY_DIR}/sender_private.pem"
SENDER_PUBLIC_FILE = f"{KEY_DIR}/sender_public.pem"
RECEIVER_PRIVATE_FILE = f"{KEY_DIR}/receiver_private.pem"
RECEIVER_PUBLIC_FILE = f"{KEY_DIR}/receiver_public.pem"

os.makedirs(KEY_DIR, exist_ok=True)

def generate_and_store_rsa_keys(private_path, public_path):
    if not os.path.exists(private_path) or not os.path.exists(public_path):
        key = RSA.generate(2048)
        with open(private_path, "wb") as priv_file:
            priv_file.write(key.export_key())
        with open(public_path, "wb") as pub_file:
            pub_file.write(key.publickey().export_key())

def load_key(file_path):
    with open(file_path, "rb") as f:
        return f.read()

def rsa_encrypt(public_key_data, data):
    rsa_key = RSA.import_key(public_key_data)
    cipher = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher.encrypt(data))

def rsa_decrypt(private_key_data, encrypted_data):
    rsa_key = RSA.import_key(private_key_data)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(encrypted_data))

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + encrypted).decode()

def aes_decrypt(key, encrypted_text):
    data = base64.b64decode(encrypted_text)
    iv, ciphertext = data[:AES.block_size], data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def sign_data(private_key_data, data):
    rsa_key = RSA.import_key(private_key_data)
    hash_obj = SHA256.new(data)
    signature = pkcs1_15.new(rsa_key).sign(hash_obj)
    return base64.b64encode(signature).decode()

def verify_signature(public_key_data, data, signature):
    rsa_key = RSA.import_key(public_key_data)
    hash_obj = SHA256.new(data)
    try:
        pkcs1_15.new(rsa_key).verify(hash_obj, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

def hybrid_encrypt(sender_priv, receiver_pub, plaintext):
    aes_key = get_random_bytes(16) 
    encrypted_key = rsa_encrypt(receiver_pub, aes_key)
    encrypted_msg = aes_encrypt(aes_key, plaintext)
    signature = sign_data(sender_priv, encrypted_msg.encode())
    return encrypted_key.decode(), encrypted_msg, signature

def hybrid_decrypt(receiver_priv, sender_pub, encrypted_key, encrypted_msg, signature):
    if not verify_signature(sender_pub, encrypted_msg.encode(), signature):
        raise ValueError("🚨 Signature Verification Failed!")

    aes_key = rsa_decrypt(receiver_priv, encrypted_key.encode())
    return aes_decrypt(aes_key, encrypted_msg)


if __name__ == "__main__":

    generate_and_store_rsa_keys(SENDER_PRIVATE_FILE, SENDER_PUBLIC_FILE)
    generate_and_store_rsa_keys(RECEIVER_PRIVATE_FILE, RECEIVER_PUBLIC_FILE)

    sender_private = load_key(SENDER_PRIVATE_FILE)
    sender_public = load_key(SENDER_PUBLIC_FILE)
    receiver_private = load_key(RECEIVER_PRIVATE_FILE)
    receiver_public = load_key(RECEIVER_PUBLIC_FILE)

    print("\n🔒 Choose an operation:")
    print("1. Encrypt & Sign")
    print("2. Decrypt & Verify")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":

        user_message = input("\n📩 Enter your secret message: ")
        print("\n🔐 Encrypting and signing the message...\n")
        enc_key, enc_msg, signature = hybrid_encrypt(sender_private, receiver_public, user_message)

        print(f"[+] Encrypted AES Key:\n{enc_key}")
        print(f"[+] Encrypted Message:\n{enc_msg}")
        print(f"[+] Digital Signature:\n{signature}")

    elif choice == "2":
        
        enc_key_input = input("\n🔑 Enter the encrypted AES key:\n").strip()
        enc_msg_input = input("\n📄 Enter the encrypted message:\n").strip()
        signature_input = input("\n✍  Enter the digital signature:\n").strip()

        print("\n🔓 Verifying signature and decrypting the message...\n")
        try:
            final_msg = hybrid_decrypt(receiver_private, sender_public, enc_key_input, enc_msg_input, signature_input)
            print(f"[✅] Message Verified and Decrypted:\n{final_msg}")
        except Exception as e:
            print(f"[❌] Error: {str(e)}")

    else:
        print("❌ Invalid choice. Please run the script again and choose 1 or 2.")