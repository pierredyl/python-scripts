# Evaluates the strength of a password by its length and entropy, returning a security score and risk score in the range of 1-10.
# Requests Pwend API https://haveibeenpwned.com/ to check if password has been breached, and how many times
# Author: Dylan Pierre
# 5/21/2026

import math
import re
import hashlib
import requests

def evaluate_password_strength() -> tuple[int, str]:
    score = 0
    password_length = 0
    
    while password_length <= 0:
        password = input("Enter the password: ")
        password_length = len(password)
        if (password_length > 64):
            print("Passwords of 64+ characters too long")
            password_length = 0
        
    # Score password length (16+ recommended, 8+ minimum, anything below is not secure)
    if password_length >= 16:
        score += 5
    elif password_length >= 8 and password_length < 16:
        score += 3
    else:
        score += 1
        
    # Score password by entropy. 
    pool_size = 0
    
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'[0-9]', password):
        pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        # Symbols [@, !, #, $, &] are usually universal used across many platforms.
        pool_size += 5
    if re.search(r'[ ]', password):
        pool_size += 1
       
    # Formula: E = L * log2(R)
    entropy = password_length * math.log2(pool_size)
    
    # 'Should' be mathmatically unbreakable with modern computing power
    if entropy >= 100:
        score += 5
    elif entropy >= 72:
        score += 3
    elif entropy >= 60:
        score += 1
        
    return score, password
    
    
    
    
def calculate_risk(score: int):
    risk = 0
    
    if score < 2:
        print("Password is not secure.")
        risk = 10
    elif score >= 2 and score < 4:
        risk = 8
        print("Password is not safe")
    elif score >= 4 and score < 8:
        print("Password is moderately safe")
        risk = 5
    elif score >=8 and score <= 10:
        print("Password very safe :)")
        risk = 1
        
    print(f"Risk Score is {risk}")
    print(f"Security Score is {score}")
    
    
    
    
    
def calculate_sha256_hash(password: str) -> str:
    password_hash = hashlib.sha256(password.encode('utf-8'))
    hex_dig = password_hash.hexdigest()
    print(f"SHA256 hash of the password: {hex_dig}")
    return hex_dig
    
    
    
    
def calculate_md5_hash(password: str) -> str:
    password_hash = hashlib.md5(password.encode('utf-8'))
    hex_dig = password_hash.hexdigest()
    print(f"MD5 hash of the password: {hex_dig}")    
    return hex_dig
    
    
    
    
    
def calculate_sha1_hash(password: str) -> str:
    password_hash = hashlib.sha1(password.encode('utf-8'))
    hex_dig = password_hash.hexdigest()
    print(f"SHA1 hash of the password: {hex_dig}")   
    return hex_dig



    
def check_password_compromise_local(sha1: str):
    found = 0
    wordlist = input("What wordlist would you like to use?: ")
    if len(wordlist) <= 0:
        print("No valid wordlist entered")
        return
    with open(wordlist, "rb") as file:
        for line in file:
            word = line.rstrip(b"\r\n")
            if hashlib.sha1(word).hexdigest() == sha1:
                found = 1
                break
    if found:
        print("Password has been compromised")
    else:
        print("Password is safe")
        
        
        
        


def check_password_compromise_online(sha1: str):
    sha1_first_five = sha1[:5]
    sha1_suffix_lower = sha1[5:]
    sha1_suffix_upper = sha1_suffix_lower.upper()
    response = requests.get(f"https://api.pwnedpasswords.com/range/{sha1_first_five}")
    
    if response.status_code != 200:
        print("Couldn't access API, using local wordlist")
        check_password_compromise_local(sha1)
        return
    
    for line in response.text.splitlines():
        suffix, breach_count = line.split(":")
        if suffix == sha1_suffix_upper:
            print(f"Password breached {breach_count} times")
            return
        
    print("Password is safe.")
        
    
    
    
    
        
if __name__ == "__main__":
    score, password = evaluate_password_strength()
    calculate_risk(score)
    sha256_hash = calculate_sha256_hash(password)
    sha1_hash = calculate_sha1_hash(password)
    md5_hash = calculate_md5_hash(password)
    check_password_compromise_online(sha1_hash)
    
        
    
