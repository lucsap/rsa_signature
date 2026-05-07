import base64

def encode_base64(data):
    return base64.b64encode(data).decode()

def decode_base64(data):
    return base64.b64decode(data.encode())