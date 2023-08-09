import hashlib
import numpy as np
from .forms import *
from .models import *
from PIL import Image
from pycipher import *
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def index(request):
    return render(request, 'index.html')

def encode(request):
    try:
        form1 = encodeform()
        mydict = {'form1': form1}
        if request.method == "POST":
            form1 = encodeform(request.POST, request.FILES)
            if form1.is_valid():
                user = form1.save(commit=False)
                user.coverimage = request.FILES['coverimage']
                user.save()
                encryptype = form1.cleaned_data['encryptype']
                plaintext = form1.cleaned_data['plaintext']
                plaintext1 = plaintext.upper()
                key1 = form1.cleaned_data['key1']
                key10 = key1.upper()
                key2 = form1.cleaned_data['key2']
                key20 = key2.upper()
                # PRIMITIVE SYMMETRIC KEY ENCRYPTION TECHNIQUES
                if encryptype == 'Vigenère Cipher':
                    k = ""
                    key1 = ''.join([c for c in key1 if c.isalpha()])
                    if not key1:
                        print("Error: The string contains no alphabetic characters")
                    else:
                        k = key1
                    j = 0
                    l = 0
                    characters = []
                    result = Vigenere(k).encipher(plaintext)
                    result1 = ""
                    for i, char in enumerate(plaintext):
                        if not char.isalpha():
                            characters.append(char)
                    for i, char in enumerate(plaintext):
                        if not char.isalpha():
                            result1 += characters[j]
                            j = j + 1
                        else:
                            result1 += result[l]
                            l = l + 1
                elif encryptype == 'Beaufort Cipher':
                    k = ""
                    key1 = ''.join([c for c in key1 if c.isalpha()])
                    if not key1:
                        print("Error: The string contains no alphabetic characters")
                    else:
                        k = key1
                    j = 0
                    l = 0
                    characters = []
                    result = Beaufort(k).encipher(plaintext)
                    result1 = ""
                    for i, char in enumerate(plaintext):
                        if not char.isalpha():
                            characters.append(char)
                    for i, char in enumerate(plaintext):
                        if not char.isalpha():
                            result1 += characters[j]
                            j = j + 1
                        else:
                            result1 += result[l]
                            l = l + 1
                elif encryptype == 'Autokey Cipher':
                    k = ""
                    key1 = ''.join([c for c in key1 if c.isalpha()])
                    if not key1:
                        print("Error: The string contains no alphabetic characters")
                    else:
                        k = key1
                    j = 0
                    l = 0
                    characters = []
                    result = Autokey(k).encipher(plaintext)
                    result1 = ""
                    for i, char in enumerate(plaintext):
                        if not char.isalpha():
                            characters.append(char)
                    for i, char in enumerate(plaintext):
                        if not char.isalpha():
                            result1 += characters[j]
                            j = j + 1
                        else:
                            result1 += result[l]
                            l = l + 1
                elif encryptype == 'Porta Cipher':
                    k = ""
                    key1 = ''.join([c for c in key1 if c.isalpha()])
                    if not key1:
                        print("Error: The string contains no alphabetic characters")
                    else:
                        k = key1
                    j = 0
                    l = 0
                    characters = []
                    result = Porta(k).encipher(plaintext)
                    result1 = ""
                    for i, char in enumerate(plaintext):
                        if not char.isalpha():
                            characters.append(char)
                    for i, char in enumerate(plaintext):
                        if not char.isalpha():
                            result1 += characters[j]
                            j = j + 1
                        else:
                            result1 += result[l]
                            l = l + 1
                # 3AES ENCRYPTION PROCESS
                def encrypt(key, data):
                    # Encrypts the data using 3 rounds of AES encryption.
                    data = pad(data)
                    cipher = Cipher(algorithms.AES(key), modes.ECB())
                    encryptor = cipher.encryptor()
                    data = encryptor.update(data) + encryptor.finalize()
                    cipher = Cipher(algorithms.AES(key), modes.ECB())
                    encryptor = cipher.encryptor()
                    data = encryptor.update(data) + encryptor.finalize()
                    cipher = Cipher(algorithms.AES(key), modes.ECB())
                    encryptor = cipher.encryptor()
                    data = encryptor.update(data) + encryptor.finalize()
                    return data
                def pad(data):
                    # Pads the data to the nearest multiple of 16 bytes.
                    padder = padding.PKCS7(algorithms.AES.block_size).padder()
                    padded_data = padder.update(data) + padder.finalize()
                    return padded_data
                def convert(key):
                    # Converts the key to a 16-byte (128-bit) key using SHA-256.
                    key_hash = hashlib.sha256(key).digest()
                    return key_hash[:16]
                key = key20.encode("utf-8")
                data = result1.encode("utf-8")
                result2 = encrypt(convert(key), data)
                result3 = str(result2)
                result_out = result3[2:-1]
                # LSB STEGANOGRAPHY ENCRYPTION          
                def encode_data_in_image(image_path, binary_string):
                    image = Image.open(image_path).convert('RGB')
                    binary_data = binary_string.encode('utf-8')
                    binary_len = len(binary_data)
                    max_size = image.width * image.height * 3 // 8
                    if binary_len > max_size:
                        raise ValueError("Data too large to be encoded in image")
                    binary_data += b'0' * (max_size - binary_len)
                    binary_data = np.array(list(binary_data), dtype=np.uint8)
                    data_bin = np.unpackbits(binary_data)
                    data_bin = np.resize(data_bin, (image.width * image.height * 3,))
                    binary_pixels = np.reshape(data_bin, (image.height, image.width, 3))
                    image_array = np.array(image)
                    stego_image_array = np.bitwise_and(image_array, 0b11111110)
                    stego_image_array += binary_pixels
                    stego_image = Image.fromarray(stego_image_array, mode='RGB')
                    stego_image.save("D:\Data Hiding Using Cryptography & Steganography\Data Hiding Using Cryptography & Steganography\steganography\stegapp\static\stegoimage\stego_image_encode.png")
                    return stego_image
                image_path = user.coverimage.path
                stego_image1 = encode_data_in_image(image_path, result_out)
                return render(request, 'encode_result.html',
                              {'result1': result1, 'plaintext1': plaintext1, 'key10': key10, 'key20': key20,
                               'encryptype': encryptype.upper(), 'result_out': result_out})
        else:
            print("Invalid Form")
            return render(request, 'encode.html', context=mydict)
    except Exception as e:
        return render(request, 'error.html')
    
def encode_result(request):
    return render(request, 'encode_result.html')

def decode(request):
    try:
        form2 = decodeform()
        mydict = {'form2': form2}
        if request.method == "POST":
            form2 = decodeform(request.POST, request.FILES)
            if form2.is_valid():
                user = form2.save(commit=False)
                user.stegoimage = request.FILES['stegoimage']
                user.save()
                image_path = user.stegoimage.path
                stego_image = Image.open(image_path)
                stego_image.save("D:\Data Hiding Using Cryptography & Steganography\Data Hiding Using Cryptography & Steganography\steganography\stegapp\static\stegoimage\stego_image_decode.png")
                decryptype = form2.cleaned_data['decryptype']
                key3 = form2.cleaned_data['key3']
                key30 = key3.upper()
                key4 = form2.cleaned_data['key4']
                key40 = key4.upper()
                # LSB STEGANOGRAPHY DECRYPTION
                def decode_data_from_image(image_path):
                    image = Image.open(image_path)
                    image_array = np.array(image)
                    binary_pixels = np.bitwise_and(image_array, 1)
                    data_bin = np.packbits(binary_pixels)
                    null_byte = data_bin.tobytes().find(b'\x00')
                    binary_data = data_bin[:null_byte]
                    return binary_data.tobytes().decode('utf-8')
                image_path = user.stegoimage.path
                encoded_data = decode_data_from_image(image_path)
                cipher2 = encoded_data.rstrip('00000')
                cipher3 = cipher2
                # 3AES DECRYPTION PROCESS
                def decrypt(key, data):
                    # Decrypts the data using 3 rounds of AES decryption.
                    cipher = Cipher(algorithms.AES(key), modes.ECB())
                    decryptor = cipher.decryptor()
                    data = decryptor.update(data) + decryptor.finalize()
                    cipher = Cipher(algorithms.AES(key), modes.ECB())
                    decryptor = cipher.decryptor()
                    data = decryptor.update(data) + decryptor.finalize()
                    cipher = Cipher(algorithms.AES(key), modes.ECB())
                    decryptor = cipher.decryptor()
                    data = decryptor.update(data) + decryptor.finalize()
                    return unpad(data)
                def unpad(data):
                    # Removes padding from the data.
                    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                    data = unpadder.update(data) + unpadder.finalize()
                    return data
                def convert(key):
                    # Converts the key to a 16-byte (128-bit) key using SHA-256.
                    key_hash = hashlib.sha256(key).digest()
                    return key_hash[:16]
                key = key40.encode("utf-8")
                encrypted_data = bytes(cipher3.encode().decode('unicode_escape'), 'latin-1')
                decrypted_data = decrypt(convert(key), encrypted_data)
                result4 = decrypted_data.decode("utf-8")
                # PRIMITIVE SYMMETRIC KEY DECRYPTION TECHNIQUES
                if decryptype == 'Vigenère Cipher':
                    k = ""
                    key3 = ''.join([c for c in key3 if c.isalpha()])
                    if not key3:
                        print("Error: The string contains no alphabetic characters")
                    else:
                        k = key3
                    j = 0
                    l = 0
                    characters = []
                    result = Vigenere(k).decipher(result4)
                    result1 = ""
                    for i, char in enumerate(result4):
                        if not char.isalpha():
                            characters.append(char)
                    for i, char in enumerate(result4):
                        if not char.isalpha():
                            result1 += characters[j]
                            j = j + 1
                        else:
                            result1 += result[l]
                            l = l + 1
                elif decryptype == 'Beaufort Cipher':
                    k = ""
                    key3 = ''.join([c for c in key3 if c.isalpha()])
                    if not key3:
                        print("Error: The string contains no alphabetic characters")
                    else:
                        k = key3
                    j = 0
                    l = 0
                    characters = []
                    result = Beaufort(k).decipher(result4)
                    result1 = ""
                    for i, char in enumerate(result4):
                        if not char.isalpha():
                            characters.append(char)
                    for i, char in enumerate(result4):
                        if not char.isalpha():
                            result1 += characters[j]
                            j = j + 1
                        else:
                            result1 += result[l]
                            l = l + 1
                elif decryptype == 'Autokey Cipher':
                    k = ""
                    key3 = ''.join([c for c in key3 if c.isalpha()])
                    if not key3:
                        print("Error: The string contains no alphabetic characters")
                    else:
                        k = key3
                    j = 0
                    l = 0
                    characters = []
                    result = Autokey(k).decipher(result4)
                    result1 = ""
                    for i, char in enumerate(result4):
                        if not char.isalpha():
                            characters.append(char)
                    for i, char in enumerate(result4):
                        if not char.isalpha():
                            result1 += characters[j]
                            j = j + 1
                        else:
                            result1 += result[l]
                            l = l + 1
                elif decryptype == 'Porta Cipher':
                    k = ""
                    key3 = ''.join([c for c in key3 if c.isalpha()])
                    if not key3:
                        print("Error: The string contains no alphabetic characters")
                    else:
                        k = key3
                    j = 0
                    l = 0
                    characters = []
                    result = Porta(k).decipher(result4)
                    result1 = ""
                    for i, char in enumerate(result4):
                        if not char.isalpha():
                            characters.append(char)
                    for i, char in enumerate(result4):
                        if not char.isalpha():
                            result1 += characters[j]
                            j = j + 1
                        else:
                            result1 += result[l]
                            l = l + 1
                return render(request, 'decode_result.html',
                              {'cipher3': cipher3, 'decryptype': decryptype.upper(), 'key30': key30, 'key40': key40,
                               'result4': result4, 'result1': result1})
        else:
            print("Invalid Form")
            return render(request, 'decode.html', context=mydict)
    except Exception as e:
        return render(request, 'error.html')
    
def decode_result(request):
    return render(request, 'decode_result.html')