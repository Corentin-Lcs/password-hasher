<h1 align="center">Password Hasher</h1>

The "Password Hasher" GitHub project is a versatile tool designed to generate passwords and hash them using a wide range of hashing algorithms. This tool is useful for security testing purposes, including brute force attacks and the creation of rainbow tables.

> [!CAUTION]  
> This tool is intended for educational purposes and security testing within ethical boundaries.

<p align="center">
  <img src="https://github.com/Corentin-Lcs/password-hasher/blob/main/DesHash.png" alt="DesHash.png"/>
</p>

## Installation

To install the necessary modules from the command prompt, run the following command:

```
pip install bcrypt hashlib scrypt argon2-cffi pycryptodome
```

> To learn more about the features of the modules, here are some useful links:
> 
> https://en.wikipedia.org/wiki/Bcrypt [EN]
> 
> https://docs.python.org/3/library/hashlib.html [EN]
> 
> https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html [EN]
> 
> https://en.wikipedia.org/wiki/Argon2 [EN]
> 
> https://www.pycryptodome.org [EN]

## Available Algorithms

The "Password Hasher" program supports the following hashing algorithms:

- `MD5`
- `SHA-224`
- `SHA-256`
- `SHA-384`
- `SHA-512`
- `SHA3-224`
- `SHA3-256`
- `SHA3-384`
- `SHA3-512`
- `ARGON2D`
- `ARGON2I`
- `ARGON2ID`
- `BCRYPT`
- `SCRYPT`
- `RIPEMD-160`

Each algorithm is implemented to deliver specific variations in security and performance tailored to different application scenarios.

> [!NOTE]  
> A sample of 5,000 passwords generated and hashed with each hashing algorithm included in the script is available in the [`examples`](https://github.com/Corentin-Lcs/password-hasher/tree/main/examples) folder.

## Project's Structure

```
password-hasher/
├─ README.md
├─ LICENSE
├─ DesHash.png
├─ examples/
│  ├─ ARGON2D.txt
│  ├─ ARGON2I.txt
│  ├─ ARGON2ID.txt
│  ├─ BCRYPT.txt
│  ├─ MD5.txt
│  ├─ RIPEMD-160.txt
│  ├─ SCRYPT.txt
│  ├─ SHA-224.txt
│  ├─ SHA-256.txt
│  ├─ SHA-384.txt
│  ├─ SHA-512.txt
│  ├─ SHA3-224.txt
│  ├─ SHA3-256.txt
│  ├─ SHA3-384.txt
│  └─ SHA3-512.txt
└─ src/
   └─ script.py
```

## Meta

Created by [@Corentin-Lcs](https://github.com/Corentin-Lcs). Feel free to contact me !

Distributed under the GNU GPLv3 license. See [LICENSE](https://github.com/Corentin-Lcs/password-hasher/blob/main/LICENSE) for more information.
