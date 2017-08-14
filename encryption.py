import string
import random
import base64
import binascii
from random import randint
from Crypto.Hash import *
from Crypto.Cipher import *
from Crypto import Random

def random_string(length, characters=string.ascii_uppercase + string.ascii_lowercase + string.digits):
	return ''.join(random.choice(characters) for _ in range(length))

def Encoding_Base64(string):
	encoded = base64.b64encode(string)
	return [encoded, ""]

def Encoding_Binary(string):
	return [bin(int(binascii.hexlify(string), 16)), ""]

def Hash_HMAC(string):
	secret = random_string(5)
	h = HMAC.new(secret)
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_MD2(string):
	h = MD2.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_MD4(string):
	h = MD4.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_MD5(string):
	h = MD5.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_RIPEMD(string):
	h = RIPEMD.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_SHA(string):
	h = SHA.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_SHA224(string):
	h = SHA224.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_SHA256(string):
	h = SHA256.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_SHA384(string):
	h = SHA384.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Hash_SHA512(string):
	h = SHA512.new()
	h.update(string)
	return [h.hexdigest(), ""]

def Cipher_AES(string):
	key = random_string(16)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CFB, iv)
	msg = iv + cipher.encrypt(string)
	return [Encoding_Base64(msg)[0], key]

def Cipher_ARC2(string):
	key = random_string(16)
	iv = Random.new().read(ARC2.block_size)
	cipher = ARC2.new(key, ARC2.MODE_CFB, iv)
	msg = iv + cipher.encrypt(string)
	return [Encoding_Base64(msg)[0], key]

def Cipher_ARC4(string):
	key = random_string(32)
	nonce = Random.new().read(16)
	tempkey = SHA.new(key+nonce).digest()
	cipher = ARC4.new(tempkey)
	msg = nonce + cipher.encrypt(string)
	return [Encoding_Base64(msg)[0], key]

def Cipher_Caesar(plaintext):
	shift = randint(1,26)
	alphabet = string.ascii_lowercase
	shifted_alphabet = alphabet[shift:] + alphabet[:shift]
	table = string.maketrans(alphabet, shifted_alphabet)
	return [plaintext.translate(table), shift]

def Cipher_Vigenere(string):
	encoded_chars = []
	key = random_string(5)
    	for i in xrange(len(string)):
        	key_c = key[i % len(key)]
        	encoded_c = chr(ord(string[i]) + ord(key_c) % 256)
        	encoded_chars.append(encoded_c)
    	encoded_string = "".join(encoded_chars)
    	return [base64.urlsafe_b64encode(encoded_string), key]

def Cipher_XOR(string):
	key = random_string(len(string))
	cipher = XOR.new(key)
	return [base64.b64encode(cipher.encrypt(string)), key]

def Encrypt(string):
	functions_list = [Encoding_Base64, Encoding_Binary, Cipher_AES, Cipher_ARC2, Cipher_ARC4, Cipher_Vigenere, Cipher_XOR, Hash_HMAC, Hash_MD2, Hash_MD4, Hash_MD5, Hash_RIPEMD, Hash_SHA, Hash_SHA224, Hash_SHA256, Hash_SHA384, Hash_SHA512, Cipher_Caesar]
	function_to_call = random.choice(functions_list)
	results = function_to_call(string)
	result = results[0]
	key = results[1]
	return [function_to_call.__name__, result, key]
