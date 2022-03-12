#!/usr/bin/env python3
# coding: utf-8

import base64
import hashlib
import random
import ast
import json
import string
import sys
from getpass import getpass


def encrypt256(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature


def encode64(string_to_code):
    message_bytes = string_to_code.encode('utf-8')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('utf-8')
    return base64_message


def decode64(coded_string):
    base64_message = coded_string
    base64_bytes = base64_message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    decoded_string = message_bytes.decode('utf-8')
    return decoded_string


def encrypt(string_to_code, hash_pass):
    alfa = list(string.ascii_lowercase)
    # CREATE SUB_LISTS
    ps1 = []
    ps2 = []
    ps3 = []
    ps4 = []
    ps5 = []
    # GENERATE A SEQUENCE
    for i1 in range(0, 5):
        ps1.append(i1)
    for i2 in range(5, 10):
        ps2.append(i2)
    for i3 in range(10, 15):
        ps3.append(i3)
    for i4 in range(15, 20):
        ps4.append(i4)
    for i5 in range(20, 26):
        ps5.append(i5)
    # RANDOMIZE SEQUENCES
    random.shuffle(ps1)
    random.shuffle(ps2)
    random.shuffle(ps3)
    random.shuffle(ps4)
    random.shuffle(ps5)
    # ADD SUB_LISTS TO A FINAL LIST
    pswitched = []
    for sq in ps1:
        pswitched.append(sq)
    for sq in ps2:
        pswitched.append(sq)
    for sq in ps3:
        pswitched.append(sq)
    for sq in ps4:
        pswitched.append(sq)
    for sq in ps5:
        pswitched.append(sq)
    # ENCODE BASE64
    encoded_string = encode64(string_to_code)
    # START ENCRYPTION
    encrypted_string = ""
    for letter in encoded_string:
        counter = 0
        found = False
        for i in alfa:
            if letter == i:
                found = True
                encrypted_string += "{}".format(alfa[pswitched[counter]])
                break
            elif letter == i.upper():
                found = True
                encrypted_string += "{}".format(alfa[pswitched[counter]].upper())
                break
            counter += 1
        if not found:
            encrypted_string += "{}".format(letter)

    # HASH OF ENCRYPTED DOCUMENT TO GUARANTEE NO CHANGES WERE MADE
    hash_k = encrypt256(encrypted_string)

    # ADD KEY TO DECRYPT
    k1 = encrypt256(hash_pass + str(ps1))
    k2 = encrypt256(hash_pass + str(ps2))
    k3 = encrypt256(hash_pass + str(ps3))
    k4 = encrypt256(hash_pass + str(ps4))
    k5 = encrypt256(hash_pass + str(ps5))

    # POSITION FOR PASS HALF WAY OF THE ENCRYPTED STRING
    position = int(len(encrypted_string) / 2)

    output = "".join((encrypted_string[:position], hash_k, k1, k2, k3, k4, k5, encrypted_string[position:]))

    # RESULT ENCRYPTED
    return output


def decrypt(encrypted_string, pswitched):
    alfa = list(string.ascii_lowercase)
    decoded_string = ""
    for letter in encrypted_string:
        counter = 0
        found = False
        for i in alfa:
            if letter == i:
                found = True
                position = 0
                for n in pswitched:
                    if n == counter:
                        decoded_string += "{}".format(alfa[position])
                        break
                    position += 1
                break
            elif letter == i.upper():
                found = True
                position = 0
                for n in pswitched:
                    if n == counter:
                        decoded_string += "{}".format(alfa[position].upper())
                        break
                    position += 1
                break
            counter += 1
        if not found:
            decoded_string += "{}".format(letter)
    # RESULT ENCRYPTED
    return str(decode64(decoded_string))


def get5(start, end, pwrd_hash, hash256):
    plis = []
    for n in range(start, end):
        plis.append(n)
    for loop in range(0, len(plis)):
        if 0 < loop < len(plis):
            plis.insert(0, plis.pop(loop))
        for i in range(0, len(plis)-1):
            lis = [plis[0], plis[1], plis[2], plis[3], plis[4]]
            if 0 < i < len(plis)-1:
                lis.insert(1, lis.pop(i+1))
            ml = [lis[0], lis[1], lis[2], lis[3], lis[4]]
            if encrypt256(pwrd_hash+str(ml)) == hash256:
                return ml
            ml = [lis[0], lis[1], lis[2], lis[4], lis[3]]
            if encrypt256(pwrd_hash+str(ml)) == hash256:
                return ml
            ml = [lis[0], lis[1], lis[3], lis[2], lis[4]]
            if encrypt256(pwrd_hash+str(ml)) == hash256:
                return ml
            ml = [lis[0], lis[1], lis[3], lis[4], lis[2]]
            if encrypt256(pwrd_hash+str(ml)) == hash256:
                return ml
            ml = [lis[0], lis[1], lis[4], lis[3], lis[2]]
            if encrypt256(pwrd_hash+str(ml)) == hash256:
                return ml
            ml = [lis[0], lis[1], lis[4], lis[2], lis[3]]
            if encrypt256(pwrd_hash+str(ml)) == hash256:
                return ml
    return None


def get6(start, end, pwrd_hash, hash256):
    plis = []
    for n in range(start, end):
        plis.append(n)
    for loop in range(0, len(plis)):
        if 0 < loop < len(plis):
            plis.insert(0, plis.pop(loop))
        for n in range(0, len(plis)-1):
            lis = [plis[0], plis[1], plis[2], plis[3], plis[4], plis[5]]
            if 0 < n < len(plis)-1:
                lis.insert(1, lis.pop(n+1))
            for i in range(0, len(lis)-1):
                li = [lis[0], lis[1], lis[2], lis[3], lis[4], lis[5]]
                if 0 < i < len(lis)-1:
                    li.insert(2, li.pop(i+1))
                # COMPARE
                ml = [li[0], li[1], li[2], li[3], li[4], li[5]]
                if encrypt256(pwrd_hash+str(ml)) == hash256:
                    return ml
                ml = [li[0], li[1], li[2], li[3], li[5], li[4]]
                if encrypt256(pwrd_hash+str(ml)) == hash256:
                    return ml
                ml = [li[0], li[1], li[2], li[4], li[3], li[5]]
                if encrypt256(pwrd_hash+str(ml)) == hash256:
                    return ml
                ml = [li[0], li[1], li[2], li[4], li[5], li[3]]
                if encrypt256(pwrd_hash+str(ml)) == hash256:
                    return ml
                ml = [li[0], li[1], li[2], li[5], li[4], li[3]]
                if encrypt256(pwrd_hash+str(ml)) == hash256:
                    return ml
                ml = [li[0], li[1], li[2], li[5], li[3], li[4]]
                if encrypt256(pwrd_hash+str(ml)) == hash256:
                    return ml
    return None


def open_file(file_to_open):
    with open(file_to_open, "r", encoding="utf-8") as file:
        json_content = json.loads(file.read())
    return str(json_content)


def get_content(file_to_open):
    with open(file_to_open, "r", encoding="utf-8") as file:
        all_content = file.read()
        position = int((len(all_content)-384) / 2)
        hash_document = all_content[position:position+64]
        k1 = all_content[position+(1*64):position + 128]
        k2 = all_content[position+(2*64):position + 192]
        k3 = all_content[position+(3*64):position + 256]
        k4 = all_content[position+(4*64):position + 320]
        k5 = all_content[position+(5*64):position + 384]
        document = all_content[:position] + all_content[position+384:]
    return [document, k1, k2, k3, k4, k5, hash_document]


if len(sys.argv) > 2:
    filename = sys.argv[1]
    if sys.argv.__contains__("-c"):
        pwrd = getpass('Password to encrypt:')
        pwrd = encrypt256(pwrd)
        ck_pwrd = getpass('Confirm password...:')
        ck_pwrd = encrypt256(ck_pwrd)
        if pwrd == ck_pwrd:
            # CODE
            content = encrypt(open_file(filename), pwrd)
            with open(filename, "w", encoding="utf-8") as arquivo:
                arquivo.write(content)
            print("File {} encrypted successfully".format(filename))
        else:
            print("Passwords didn't match! Try again and type carefully")
    elif sys.argv.__contains__("-d"):
        pwrd = getpass('Password:')
        pwrd = encrypt256(pwrd)
        # DECODE
        content = get_content(filename)
        hash_doc = encrypt256(content[0])
        # CHECK IF FILE WAS MODIFIED
        if content[6] == hash_doc or sys.argv.__contains__("-i"):
            if sys.argv.__contains__("-i"):
                print("Ignoring verification of changes made on file while encrypted")
            key1 = get5(0, 5, pwrd, content[1])
            key2 = get5(5, 10, pwrd, content[2])
            key3 = get5(10, 15, pwrd, content[3])
            key4 = get5(15, 20, pwrd, content[4])
            key5 = get6(20, 26, pwrd, content[5])
            if key1 is not None and key2 is not None and key3 is not None and key4 is not None and key5 is not None:
                pswitch = []
                for sequence in key1:
                    pswitch.append(sequence)
                for sequence in key2:
                    pswitch.append(sequence)
                for sequence in key3:
                    pswitch.append(sequence)
                for sequence in key4:
                    pswitch.append(sequence)
                for sequence in key5:
                    pswitch.append(sequence)
                decoded = decrypt(content[0], pswitch)
                entry_json = json.dumps(ast.literal_eval(decoded), indent=4, ensure_ascii=False)
                with open(filename, "w", encoding="utf-8") as arquivo:
                    arquivo.write(entry_json)
                print("File {} decrypted successfully".format(filename))
            else:
                print("Wrong password")
        else:
            print("File was modified")
    else:
        print("Invalid option use filename plus -c to code and -d to decode")
else:
    print("Missing arguments...")
    print("crypter jsonfilename.json -c (encrypt)")
    print("crypter jsonfilename.json -d (decrypt)")