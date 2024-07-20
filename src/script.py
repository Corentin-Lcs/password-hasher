import bcrypt
import hashlib
import random
import scrypt
import string
from argon2.low_level import hash_secret, Type
from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512, RIPEMD160
from os.path import exists, getsize

# Hash functions.
def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha224(password):
    return hashlib.sha224(password.encode()).hexdigest()

def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_sha384(password):
    return hashlib.sha384(password.encode()).hexdigest()

def hash_sha512(password):
    return hashlib.sha512(password.encode()).hexdigest()

def hash_sha3_224(password):
    return SHA3_224.new(password.encode()).hexdigest()

def hash_sha3_256(password):
    return SHA3_256.new(password.encode()).hexdigest()

def hash_sha3_384(password):
    return SHA3_384.new(password.encode()).hexdigest()

def hash_sha3_512(password):
    return SHA3_512.new(password.encode()).hexdigest()

def hash_argon2d(password):
    return hash_secret(password.encode(), salt=b'somesalt', time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=Type.D).hex()

def hash_argon2i(password):
    return hash_secret(password.encode(), salt=b'somesalt', time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=Type.I).hex()

def hash_argon2id(password):
    return hash_secret(password.encode(), salt=b'somesalt', time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=Type.ID).hex()

def hash_bcrypt(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def hash_scrypt(password):
    return scrypt.hash(password.encode(), salt=b'salt', N=16384, r=8, p=1).hex()

def hash_ripemd160(password):
    h = RIPEMD160.new()
    h.update(password.encode())
    return h.hexdigest()

# Hash functions dictionary.
hash_functions = {
    "MD5": hash_md5,
    "SHA-224": hash_sha224,
    "SHA-256": hash_sha256,
    "SHA-384": hash_sha384,
    "SHA-512": hash_sha512,
    "SHA3-224": hash_sha3_224,
    "SHA3-256": hash_sha3_256,
    "SHA3-384": hash_sha3_384,
    "SHA3-512": hash_sha3_512,
    "ARGON2D": hash_argon2d,
    "ARGON2I": hash_argon2i,
    "ARGON2ID": hash_argon2id,
    "BCRYPT": hash_bcrypt,
    "SCRYPT": hash_scrypt,
    "RIPEMD-160": hash_ripemd160
}

def generate_password(length=25):
    """
    Generates a random password of the specified length.
    
    Args:
        length (int): The length of the password to generate. Default is 25.
        
    Returns:
        str: A randomly generated password.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def write_to_file(password, hash_function, algo_name):
    """
    Writes a password and its hash to a specified file.
    
    Args:
        password (str): The password to write.
        hash_function (callable): The hash function to use.
        algo_name (str): The name of the algorithm.
    """
    hashed = hash_function(password)
    file_path = f"{algo_name}.txt"
    line_length = len(password) + 11 + len(hashed)
    if not exists(file_path) or getsize(file_path) == 0:
        with open(file_path, 'w') as file:
            header = f"{'Password':<{len(password)}}     |     {algo_name}"
            file.write(header + "\n")
            file.write(f"{'-' * line_length}\n")
    with open(file_path, 'a') as file:
        file.write(f"{password}     |     {hashed}\n")

def list_algorithms():
    """Prints the list of available algorithms with their numbers."""
    print("|-> Algorithm List\n")
    for idx, algo_name in enumerate(hash_functions.keys(), 1):
        print(f"{idx}. {algo_name}")

def write_to_files():
    """Prompts the user to choose a mode and writes passwords and their hashes accordingly."""
    list_algorithms()
    mode = input("\nEnter the algorithm number or 'all' to use all algorithms: ").strip()
    if mode.lower() == 'all':
        while True:
            password = generate_password()
            for algo_name, hash_function in hash_functions.items():
                write_to_file(password, hash_function, algo_name)
    else:
        try:
            algo_index = int(mode)
            if 1 <= algo_index <= len(hash_functions):
                algo_name = list(hash_functions.keys())[algo_index - 1]
                hash_function = hash_functions[algo_name]
                while True:
                    password = generate_password()
                    write_to_file(password, hash_function, algo_name)
            else:
                print("Invalid algorithm number. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number or 'all'.")

print("\n|------------------------------[ Password Hasher ]------------------------------|\n")
write_to_files()