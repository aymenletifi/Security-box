import base64

class Encoding:

    @classmethod
    def encode(self, method, data):
        if(method in ["utf8", "ascii"]):
            text = data.encode(method)
            return text

        elif(method == "base64"):
            message = data.encode("ascii")
            base64_bytes = base64.b64encode(message)
            base64_message = base64_bytes.decode("ascii")
            return base64_message

        elif(method == "base32"):
            message = data.encode("ascii")
            base32_bytes = base64.b32encode(message)
            base32_message = base32_bytes.decode("ascii")
            return base32_message

        elif(method == "base16"):
            message = data.encode("ascii")
            base16_bytes = base64.b32encode(message)
            base16_message = base16_bytes.decode("ascii")
            return base16_message

    @classmethod
    def decode(self, method, data):
        if(method in ["utf8", "ascii"]):
            decoded_data = data.decode(method)
            return decoded_data

        elif(method == "base64"):
            message_bytes = data.encode("ascii")
            base64_bytes = base64.b64decode(message_bytes)
            base64_message = base64_bytes.decode("ascii")
            return base64_message

        elif(method == "base32"):
            message_bytes = data.encode("ascii")
            base32_bytes = base64.b32decode(message_bytes)
            base32_message = base32_bytes.decode("ascii")
            return base32_message

        elif(method == "base16"):
            message_bytes = data.encode("ascii")
            base16_bytes = base64.b32decode(message_bytes)
            base16_message = base16_bytes.decode("ascii")
            return base16_message
