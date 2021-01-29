import hashlib

class Hashing:

    @classmethod
    def hash(self, algo, message):
        encoded = message.encode()
        if(algo == "md5"):
            return hashlib.md5(encoded).hexdigest()
        elif(algo == "sha1"):
            return hashlib.sha1(encoded).hexdigest()
        elif(algo == "sha256"):
            return hashlib.sha256(encoded).hexdigest()
        elif(algo == "sha512"):
            return hashlib.sha512(encoded).hexdigest()
    
    @classmethod
    def crack(self, algo, hach):
        words = open("dict.txt", "r").readlines()

        for word in words:
            if (self.hash(algo, word.strip()) == hach):
                return word

        return None
