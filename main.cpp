#include <iostream>
#include <string>

using namespace std;

void getMessageToEncrypt() {
    cout << "Enter the message to encrypt: ";
    string message;
    getline(cin, message);
}

int main() {
    getMessageToEncrypt();
    return 0;
}