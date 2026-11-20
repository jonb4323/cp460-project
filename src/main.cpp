#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <cstdint>

using namespace std;

uint8_t plaintext;
uint8_t key;
uint8_t iv;
uint8_t ciphertext;
uint8_t tag;
    
void getDataToEncrypt() {
    cout << "Enter data to encrypt: ";
    cin >> plaintext;
}

int gcm_encrypt(const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& tag) 
    {
    return 0;
}

int main() {
    getDataToEncrypt();
    //gcm_encrypt(plaintext, key, iv, ciphertext, tag);
    return 0;
}