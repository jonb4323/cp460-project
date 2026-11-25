CP460 Project (AES-128-GCM)
A C++ command-line program that demonstrates authenticated encryption with AES-128 in Galois/Counter Mode (GCM) using the OpenSSL EVP API.
It encrypts a line of user input, prints every component of the result (key, IV, ciphertext, auth tag), decrypts it again, and verifies the round trip.
A built-in test suite checks correctness against a NIST known-answer vector and demonstrates that GCM detects tampering.

---

Features
- AES-128-GCM encryption and decryption through OpenSSL's `EVP_*` interface
- Random key and IV generation with `RAND_bytes`
- Additional Authenticated Data (AAD) support ("cp460-project" in the demo)
- 128-bit authentication tag, verified on decrypt
- Test suite covering known answers, tampering, determinism and edge cases

Parameters
Parameter     Value                  Notes
----------    -------------------    -------------------------------------------------
Algorithm     AES-128-GCM            EVP_aes_128_gcm()
Key length    16 bytes (128 bits)    Randomly generated per run
IV length     1 byte (8 bits)        Shortened on purpose (default = 12 bytes)
Tag length    16 bytes (128 bits)    Full-length authentication tag
AAD           "cp460-project"        Authenticated but not encrypted

Requirements
- g++
- OpenSSL development libraries (1.1.1 or 3.x)

Build
g++ -std=c++17 -Wall -Wextra main.cpp -o main -lssl -lcrypto

Usage
You are prompted for a line of text. The program then generates a fresh key and IV, encrypts, prints the results in hex, decrypts, and confirms the plaintext matches.

Example session (values will differ on every run):
=========================================
Enter data to encrypt: hello world

Key: <32 hex characters>
Initialization Vector: <2 hex characters>
Ciphertext: <hex, same length as the plaintext>
Auth Tag: <32 hex characters>

Decrypted: hello world
Does the plaintext match in -> out?: matches original
=========================================

Test mode
run ./main test

Runs the full test suite and prints a pass/fail summary at the end.

TEST SUITE
==========
 
1. Data in == data out
   Encrypting then decrypting "SECRET KEY is 9404" returns the original
   message.
 
2. Sizes
   Key and tag are 16 bytes each, and the ciphertext is the same length as
   the plaintext (GCM is a stream-style mode with no padding).
 
3. NIST known answer
   With an all-zero key, 12-byte all-zero IV, no AAD and a 16-byte all-zero
   plaintext, the output matches the published GCM test vector:
     ciphertext: 0388dace60b6a392f328c2b971b2fe78
     tag:        ab6e47d42cec13bdf53a67b21257bddf
 
4. Tampering
   An untouched message decrypts (control). Decryption fails if one bit of
   the ciphertext, tag or IV is flipped, if a different key is used, or if
   the AAD differs.
 
5. Determinism and IV sensitivity
   Same key, IV and input produce identical output twice. Changing only the
   IV changes both the ciphertext and the tag.
 
6. Edge cases
   A 1-byte message and a 256-byte message containing every possible byte
   value both round-trip correctly.
 
A successful run ends with a line like: Test Summary: N passed, 0 failed
 
 
CODE OVERVIEW
Function                        Purpose
------------------------------  ------------------------------------------------
getDataToEncrypt()              Reads a line from stdin into plaintext

randomBytes(n)                  Returns n cryptographically secure random bytes
 
gcm_encrypt()                   Encrypts plaintext into ciphertext and produces
                                tag
 
gcm_decrypt()                   Decrypts ciphertext into decryptedtext and
                                verifies tag; returns the plaintext length, or
                                -1 on authentication failure
 
stringToBytes() / toString()    Convert between std::string and
                                std::vector<uint8_t>
 
bytesToHex()                    Hex-encodes a byte vector for display
 
handleErrors()                  Prints the OpenSSL error queue and aborts
 
run_tests()                     Executes the test suite

All state (`key`, `iv`, `aad`, `plaintext`, `ciphertext`, `tag`, `decryptedtext`) is held in global vectors for simplicity.

How encryption works
1. Create a cipher context and select `EVP_aes_128_gcm()`.
2. Set the IV length (needed because it is not the default 12 bytes).
3. Load the key and IV.
4. Feed in the AAD (authenticated only).
5. Encrypt the plaintext.
6. Finalise, then retrieve the 16-byte tag.

Decryption follows the same steps, but the expected tag is supplied before finalising. If `EVP_DecryptFinal_ex` does not return a positive value,
the output is discarded and the function returns `-1`, so unauthenticated plaintext is never released.

Security Notes
- 1-byte IV is insecure
- Keys are printed to stdout
- Key management is out of scope
- Test 5 encrypts twice with the same key and IV on purpose

Project Structure
├── main.cpp
└── README.md

References
- [OpenSSL wiki: EVP Authenticated Encryption and Decryption](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
- [NIST SP 800-38D: Recommendation for GCM and GMAC](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)"](https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf)