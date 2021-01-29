from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import binascii

class SymEncryption:

    @classmethod
    def encrypt(self, algo, mdp, message):
        message = str.encode(message)
        mdp = str.encode(mdp)

        # use random intervals
        if algo == "aes128":
            while len(mdp) < 16:
                mdp = mdp + mdp
            
            mdp = mdp[:16]
            aes = AES.new(mdp, AES.MODE_CBC)

            encrypted = aes.encrypt(pad(message, 16))

            return binascii.hexlify(b"0" + aes.iv + encrypted).decode("utf-8")
        elif algo == "aes256":
            while len(mdp) < 32:
                mdp = mdp + mdp

            mdp = mdp[:32]
            aes = AES.new(mdp, AES.MODE_CBC)

            encrypted = aes.encrypt(pad(message, 32))

            return binascii.hexlify(b"1" + aes.iv + encrypted).decode("utf-8")
        elif algo == "des":
            while len(mdp) < 8:
                mdp = mdp + mdp

            mdp = mdp[:8]

            des = DES.new(mdp, DES.MODE_CBC)
            encrypted = des.encrypt(pad(message, 8))

            return binascii.hexlify(b"2" + des.iv + encrypted).decode("utf-8")

    @classmethod
    def decrypt(self, mdp, enc_message):
        enc_message = binascii.unhexlify(enc_message.encode("utf-8"))
        algo = ""
        iv = b""
        if enc_message[0] == ord(b"0"):
            algo = "aes128"
            iv = enc_message[1:17]
            enc_message = enc_message[17:]
        elif enc_message[0] == ord(b"1"):
            algo = "aes256"
            iv = enc_message[1:17]
            enc_message = enc_message[17:]
        elif enc_message[0] == ord(b"2"):
            iv = enc_message[1:9]
            enc_message = enc_message[9:]
            algo = "des"

        mdp = str.encode(mdp)

        if algo == "aes128":
            while len(mdp) < 16:
                mdp = mdp + mdp

            mdp = mdp[:16]

            aes = AES.new(mdp, AES.MODE_CBC, iv=iv)
            message = aes.decrypt(enc_message)
            return ("aes128", message.strip(b"\x0b").decode("utf-8"))

        elif algo == "aes256":
            while len(mdp) < 32:
                mdp = mdp + mdp

            mdp = mdp[:32]

            aes = AES.new(mdp, AES.MODE_CBC, iv=iv)
            message = aes.decrypt(enc_message)

            return ("aes256", message.strip(b"\x0b").decode("utf-8"))
        elif algo == "des":
            while len(mdp) < 8:
                mdp = mdp + mdp

            mdp = mdp[:8]

            des = DES.new(mdp, DES.MODE_CBC, iv=iv)
            message = des.decrypt(enc_message)

            return ("des", message.strip(b"\x0b").decode("utf-8"))
        else:
            return (None, None)
