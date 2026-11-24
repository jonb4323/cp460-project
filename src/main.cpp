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

constexpr size_t KEY_LEN = 16; // AES 128 key length
constexpr size_t IV_LEN = 1; // (2^8) shortened on purpose for readability (default = 12)
constexpr size_t TAG_LEN = 16; // 128 bit auth tag length

vector<uint8_t> plaintext; // data the user typed in
vector<uint8_t> key; // 16 byte AES key
vector<uint8_t> iv; // 8 bit
vector<uint8_t> aad; // additional authenticated data
vector<uint8_t> ciphertext; // output of encrypt  
vector<uint8_t> tag; // 16 byte authentication tag
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
    getline(cin, input); // read the entire line
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
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()))
        handleErrors();


    /* Provide any AAD data. This can be called zero or more times as required */
    if (!aad.empty()) {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad.data(), static_cast<int>(aad.size())))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output. EVP_EncryptUpdate can be called multiple times if necessary. */
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
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
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

    /* Provide the message to be decrypted, and obtain the plaintext output. EVP_DecryptUpdate can be called multiple times if necessary. */
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

// testing
int passed = 0, failed = 0;

string check(bool ok) {
    if (ok) passed++; else failed++;
    return (ok ? "[PASS] " : "[FAIL] ");
}

// fresh test load
void encryptFresh(string msg) {
    plaintext = stringToBytes(msg);
    key = randomBytes(KEY_LEN);
    iv = randomBytes(IV_LEN);
    aad = stringToBytes("cp460-project");
    gcm_encrypt();
}

void run_tests() {
    // TEST 1: in/out match
    cout << "===TEST 1: Data in == Data out===\n\n";
    cout << "[Data In]: SECRET KEY is 9404\n";

    encryptFresh("SECRET KEY is 9404");                                                                                                                                                                                                                         
    string test1_status = check(gcm_decrypt() >= 0 && toString(decryptedtext) == "SECRET KEY is 9404");

    cout << "[Data Out]: " + toString(decryptedtext) + "\n";
    cout << "\nVerifying...\n\n";
    cout << "TEST 1 STATUS: " + test1_status + "\n";

    // TEST 2: sizes
    cout << "\n===TEST 2: Key & Tag == 16 bytes & length cipher == length plaintext===\n\n";

    string test2_status_1 = check(key.size() == 16 && tag.size() == 16);
    string test2_status_2 = check(ciphertext.size() == plaintext.size());

    cout << "Verifying...\n\n";
    cout << "TEST 2.1 STATUS: " + test2_status_1 + "\n";
    cout << "TEST 2.2 STATUS: " + test2_status_2 + "\n";

    // TEST 3: expected output
    cout << "\n===TEST 3: Expected Output, matches NIST known anwser===\n\n";
    cout << "Assigning new values...\n";

    key.assign(16, 0);
    iv.assign(12, 0);
    aad.clear();
    plaintext.assign(16, 0);

    cout << "Encrypting...\n";

    gcm_encrypt();
    string test3_status = check(bytesToHex(ciphertext) == "0388dace60b6a392f328c2b971b2fe78" && bytesToHex(tag) == "ab6e47d42cec13bdf53a67b21257bddf");

    cout << "\nVerifying...\n\n";
    cout << "TEST 3 STATUS: " + test3_status + "\n";

    // TEST 4: tampering
    cout << "\n===TEST 4: Tampering===\n\n";
    encryptFresh("dont change me");
    cout << "[Control]: untouched ciphertext and tag should decrypt";
    string test4_status_1 = check(gcm_decrypt() >= 0);

    ciphertext[0] ^= 1;
    cout << "\n[Flip 1 bit of the ciphertext]: tag no longer matches";
    string test4_status_2 = check(gcm_decrypt() < 0);

    encryptFresh("dont change me");
    tag[0] ^= 1;
    cout << "\n[Flip 1 bit of the auth tag]: continuing...";
    string test4_status_3 = check(gcm_decrypt() < 0);

    encryptFresh("dont change me");
    iv[0] ^= 1;
    cout << "\n[Flip 1 bit of the IV]: wrong keystream and tag";
    string test4_status_4 = check(gcm_decrypt() < 0);

    encryptFresh("dont change me");
    key = randomBytes(KEY_LEN);
    cout << "\n[Decrypt with a different key]: continuing...";
    string test4_status_5 = check(gcm_decrypt() < 0);

    encryptFresh("dont change me");
    aad = stringToBytes("wrong aad");
    cout << "\n[Decrypt with different AAD]: continuing...\n";
    string test4_status_6 = check(gcm_decrypt() < 0);

    cout << "\nVerifying...\n\n";
    cout << "TEST 4.1 STATUS: " + test4_status_1 + "\n";
    cout << "TEST 4.2 STATUS: " + test4_status_2 + "\n";
    cout << "TEST 4.3 STATUS: " + test4_status_3 + "\n";
    cout << "TEST 4.4 STATUS: " + test4_status_4 + "\n";
    cout << "TEST 4.5 STATUS: " + test4_status_5 + "\n";
    cout << "TEST 4.6 STATUS: " + test4_status_6 + "\n";

    // TEST 5: verifying the key, i/o and iv
    cout << "\n===TEST 5: Verifying Key, I/O and IV===\n\n";
    key.assign(16, 7); iv.assign(1, 5);
    aad = stringToBytes("cp460-project");
    plaintext = stringToBytes("same input");

    gcm_encrypt();
    vector<uint8_t> c1 = ciphertext, t1 = tag;
    gcm_encrypt();

    cout << "[Same key, IV and input encrypted twice]: output should be identical\n";
    string test5_status_1 = check(ciphertext == c1 && tag == t1);

    iv[0] = 6;
    gcm_encrypt();
    cout << "[Change only the IV]: ciphertext and tag should both change\n";
    string test5_status_2 = check(ciphertext != c1 && tag != t1 && ciphertext.size() == c1.size());

    cout << "\nVerifying...\n\n";
    cout << "TEST 5.1 STATUS: " + test5_status_1 + "\n";
    cout << "TEST 5.2 STATUS: " + test5_status_2 + "\n";

    // TEST 6: edge cases
    cout << "\n===TEST 6: Edge Cases===\n\n";
    encryptFresh("a");
    cout << "[Smallest message 1 byte]: should decrypt back to the original\n";

    string test6_status_1 = check(gcm_decrypt() >= 0 && decryptedtext == plaintext);

    string bin;
    for (int i = 0; i < 256; i++) bin.push_back(static_cast<char>(i));

    encryptFresh(bin);
    cout << "[Binary data all 256 byte values]: should decrypt back to the original\n";

    string test6_status_2 = check(gcm_decrypt() >= 0 && decryptedtext == plaintext);

    cout << "\nVerifying...\n\n";
    cout << "TEST 6.1 STATUS: " + test6_status_1 + "\n";
    cout << "TEST 6.2 STATUS: " + test6_status_2 + "\n";

    // test summary
    cout << "\nTest Summary: " << passed << " passed, " << failed << " failed" << endl;
}

int main(int argc, char* argv[]) {
    cout << "\n=========================================\n";

    // ./main.exe test
    if (argc > 1 && string(argv[1]) == "test") {
        run_tests();
        return 0;
    }

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
        cout << "\nDecrypted: " << toString(decryptedtext) << endl;
        cout << (decryptedtext == plaintext ? "Does the plaintext match in -> out?: matches original" : "MISMATCH") << endl;
    } else { cout << "Decryption failed (authentication error)" << endl; }

    cout << "=========================================\n\n";
    return 0;
}
