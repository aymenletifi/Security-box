from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
import binascii
import elgamal
import json
from os import path

class AsymEncryption:
    
    @classmethod
    def gen_RSA_keypair(self, mdp, nom):
        pair = RSA.generate(4096)

        f = open(f"{nom}.key.rsa", "wb")
        f.write(pair.export_key(passphrase=mdp))
        f.close()

        return pair

    @classmethod
    def RSA_keypair_exists(self, nom):
        return path.exists(f"{nom}.key.rsa")

    @classmethod
    def RSA_get_keypair(self, mdp, nom):
        return RSA.import_key(open(f"{nom}.key.rsa", "rb").read(), mdp)

    @classmethod
    def RSA_encrypt(self, message, paire):
        message = message.encode("utf-8")
        encryptor = PKCS1_OAEP.new(paire.publickey())

        encrypted = encryptor.encrypt(message)
        return binascii.hexlify(encrypted).decode("utf-8")

    @classmethod
    def RSA_decrypt(self, encrypted, paire):
        decryptor = PKCS1_OAEP.new(paire)
        decrypted = decryptor.decrypt(binascii.unhexlify(encrypted.encode("utf-8")))
        
        return decrypted.decode("utf-8")

    @classmethod
    def RSA_sign(self, message, paire):
        hach = int.from_bytes(SHA512.new(message.encode("utf-8")).digest(), byteorder="big")
        sig = pow(hach, paire.d, paire.n)
        return sig

    @classmethod
    def RSA_verify(self, message, sig, paire):
        hach = int.from_bytes(SHA512.new(message.encode("utf-8")).digest(), byteorder="big")
        sig = int(sig)
        calcHash = pow(sig, paire.e, paire.n)
        return calcHash == hach


    @classmethod
    def gen_ElGamal_keypair(self, nom):
        paire = elgamal.generate_keys()

        with open(f"{nom}.key.elgamal", "w") as f:
            json.dump({"g": paire["publicKey"].g, "p": paire["publicKey"].p, "x": paire["privateKey"].x,
                "y": paire["publicKey"].h, "bitness": paire["publicKey"].iNumBits}, f, sort_keys=True)

        return paire

    @classmethod
    def ElGamal_keypair_exists(self, nom):
        return path.exists(f"{nom}.key.elgamal")

    @classmethod
    def ElGamal_get_keypair(self, nom):
        paire = None
        with open(f"{nom}.key.elgamal", "r") as f:
            paire = json.load(f)
        
        return {"publicKey": elgamal.PublicKey(g=paire["g"], p=paire["p"], h=paire["y"], iNumBits=paire["bitness"]),
                "privateKey": elgamal.PrivateKey(g=paire["g"], p=paire["p"], x=paire["x"], iNumBits=paire["bitness"])}

    @classmethod
    def ElGamal_encrypt(self, message, paire):
        return elgamal.encrypt(paire["publicKey"], message)

    @classmethod
    def ElGamal_decrypt(self, encrypted, paire):
        return elgamal.decrypt(paire["privateKey"], encrypted)
