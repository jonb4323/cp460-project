#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;

constexpr size_t KEY_LEN = 32; // AES 256 key length
constexpr size_t IV_LEN = 12; // 96 bit nonce length (default for GCM)
constexpr size_t TAG_LEN = 16; // 128 bit auth tag length

vector<uint8_t> plaintext; // data the user typed in
vector<uint8_t> key; // 32-byte AES key (random)
vector<uint8_t> iv; // 12-byte IV (random, new per message)
vector<uint8_t> aad; // additional authenticated data
vector<uint8_t> ciphertext; // output of encrypt
vector<uint8_t> tag; // 16-byte authentication tag
vector<uint8_t> decryptedtext; // output of decrypt
    
void handleErrors() { // unexpected error handling
    ERR_print_errors_fp(stderr);
    abort();
}

vector<uint8_t> stringToBytes(const string& s) { // convert a string to bytes
    return vector<uint8_t>(s.begin(), s.end());
}

string toString(const vector<uint8_t>& v) {  
    return string(v.begin(), v.end()); 
}

void getDataToEncrypt() { // get data from user
    cout << "Enter data to encrypt: ";
    string input;
    getline(cin, input); // use getline to read the entire line
    plaintext = stringToBytes(input);
}

vector<uint8_t> randomBytes(size_t n) { // generate random bytes for key and IV
    vector<uint8_t> buf(n);
    if (1 != RAND_bytes(buf.data(), static_cast<int>(n)))
        handleErrors();
    return buf;
}

string bytesToHex(const vector<uint8_t>& bytes) { // convert bytes to hex string
    ostringstream oss; // build hex string
    for (uint8_t b : bytes)
        oss << hex << setw(2) << setfill('0') << static_cast<int>(b);
    return oss.str();
}

// Encrypt data
int gcm_encrypt() {
    EVP_CIPHER_CTX *ctx;

    int len = 0;
    int ciphertext_len = 0;

    ciphertext.assign(plaintext.size(), 0);
    tag.assign(TAG_LEN, 0);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()))
        handleErrors();

    /* Provide any AAD data. This can be called zero or more times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad.data(), static_cast<int>(aad.size())))
        handleErrors();

    /* 
    Provide the message to be encrypted, and obtain the encrypted output.
    EVP_EncryptUpdate can be called multiple times if necessary
    */
    if(!plaintext.empty()) {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())))
            handleErrors();
        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at this stage, but this does not occur in GCM mode */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len))
        handleErrors();
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(TAG_LEN), tag.data()))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Decrypt data
int gcm_decrypt() {
    EVP_CIPHER_CTX *ctx;

    int len = 0;
    int plaintext_len = 0;
    int ret;

    // make room for the output
    decryptedtext.assign(ciphertext.size(), 0);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()))
        handleErrors();

    /* Provide any AAD data. This can be called zero or more times as required */
    if(!aad.empty()) {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad.data(), static_cast<int>(aad.size())))
            handleErrors();
    }

    /*
    * Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(!ciphertext.empty()) {
        if(!EVP_DecryptUpdate(ctx, decryptedtext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())))
            handleErrors();
        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success, anything else is a failure - the plaintext is not trustworthy. */
    ret = EVP_DecryptFinal_ex(ctx, decryptedtext.data() + plaintext_len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) { // success
        plaintext_len += len;
        decryptedtext.resize(plaintext_len);
        return plaintext_len;
    } else { // verify failed
        decryptedtext.clear();
        return -1;
    }
}

int main() {
    getDataToEncrypt(); // gather data from user to encrypt

    // need to generate the fresh key and iv for each run
    key = randomBytes(KEY_LEN);
    iv = randomBytes(IV_LEN);
    aad = stringToBytes("cp460-project");

    // encrypt
    gcm_encrypt();
    cout << "\nKey: " << bytesToHex(key) << endl;
    cout << "Initialization Vector: " << bytesToHex(iv) << endl;
    cout << "Ciphertext: " << bytesToHex(ciphertext) << endl;
    cout << "Auth Tag: " << bytesToHex(tag) << endl;

    // decrypt
    if (gcm_decrypt() >= 0) {
        cout << "\nDecrypted  : " << toString(decryptedtext) << endl;
        cout << (decryptedtext == plaintext ? "Round trip OK: matches original" 
                                            : "MISMATCH") << endl;
    } else {
        cout << "Decryption failed (authentication error)" << endl;
    }

    /*
    // testing
    if (test_enabled) {
        run_tests();
    } */

    return 0;
}