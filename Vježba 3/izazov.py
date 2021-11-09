from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os

def verify_MAC(key, mac, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(mac)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":

    path = os.path.join("challenges", "nikolic_malora_duje", "mac_challenge")
    print(path)

    key = "nikolic_malora_duje".encode()
    
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"

        with open(path + "\\" + msg_filename, "rb") as file:
            message = file.read()

        with open(path +  "\\" + sig_filename, "rb") as file:
            mac = file.read()

        is_authentic = verify_MAC(key, mac, message)

        print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')
