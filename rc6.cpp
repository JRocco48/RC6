#include <iostream>
#include <string>
#include <algorithm>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>
#include <fstream>

using namespace std;

unsigned int leftRotate(unsigned int a, unsigned int b) {
    return (a << b)|(a >> (32 - b));
}

unsigned int rightRotate(unsigned int a, unsigned int b) {
    return (a >> b)|(a << (32 - b));
}

string encrypt(string key, string plaintext) {
    //initialization
    unsigned int p32 = 0xB7E15163;
    unsigned int q32 = 0x9E3779B9;
    int c = (key.size() * 4)/32;
    
    unsigned int l[c];
    for (int i = 0; i < key.size()/8; i++) {
        string temp = key.substr(8*i, 8);
        temp = temp.substr(6, 2) + temp.substr(4, 2) + temp.substr(2, 2) + temp.substr(0, 2);
        l[i] = stoul(temp, nullptr, 16);
    }
    
    //key schedule procedure
    unsigned int s[(2*20) + 3];
    s[0] = p32;
    for(int i = 1; i < (2*20) + 4; i++) {
        s[i] = s[i-1] + q32;
    }
    int a, b, i, j;
    a = b = i = j = 0;
    int v = 3 * max(c, (2*20) + 4);
    for(int iter = 1; iter < v + 1; iter++) {
        a = s[i] = leftRotate(s[i] + a + b, 3);
        b = l[j] = leftRotate(l[j] + a + b, a + b);
        i = (i + 1) % ((2*20)+4);
        j = (j + 1) % c;
    }
    
    string sA = plaintext.substr(0, 8);
    string sB = plaintext.substr(8, 8);
    string sC = plaintext.substr(16, 8);
    string sD = plaintext.substr(24, 8);
    
    /** 
    reverse so first byte of plaintext is placed in least significant byte of A
    and last byte of plaintext is placed in most significant byte of D
    **/
    
    sA = sA.substr(6, 2) + sA.substr(4, 2) + sA.substr(2, 2) + sA.substr(0, 2);
    sB = sB.substr(6, 2) + sB.substr(4, 2) + sB.substr(2, 2) + sB.substr(0, 2);
    sC = sC.substr(6, 2) + sC.substr(4, 2) + sC.substr(2, 2) + sC.substr(0, 2);
    sD = sD.substr(6, 2) + sD.substr(4, 2) + sD.substr(2, 2) + sD.substr(0, 2);
    
    unsigned int hA = stoul(sA, nullptr, 16);
    unsigned int hB = stoul(sB, nullptr, 16);
    unsigned int hC = stoul(sC, nullptr, 16);
    unsigned int hD = stoul(sD, nullptr, 16);
    
    //encryption procedure
    hB += s[0];
    hD += s[1];
    for(int iter = 1; iter < 21; iter++) {
        unsigned int t = leftRotate(hB * (2 * hB + 1), 5);
        unsigned int u = leftRotate(hD * (2 * hD + 1), 5);
        hA = leftRotate(hA ^ t, u) + s[2 * iter];
        hC = leftRotate(hC ^ u, t) + s[(2 * iter) + 1];
        
        //(hA, hB, hC, hD) = (hB, hC, hD, hA)
        unsigned int temp = hA;
        hA = hB;
        hB = hC;
        hC = hD;
        hD = temp;
    }
    hA += s[(2*20) + 2];
    hC += s[(2*20) + 3];
    
    stringstream streamA, streamB, streamC, streamD;
    streamA << hex << hA;
    streamB << hex << hB;
    streamC << hex << hC;
    streamD << hex << hD;
    
    string outputA = streamA.str();
    while(outputA.size() < 8) outputA = "0" + outputA;
    outputA = outputA.substr(6, 2) + outputA.substr(4, 2) + outputA.substr(2, 2) + outputA.substr(0, 2);
    
    string outputB = streamB.str();
    while(outputB.size() < 8) outputB = "0" + outputB;
    outputB = outputB.substr(6, 2) + outputB.substr(4, 2) + outputB.substr(2, 2) + outputB.substr(0, 2);
    
    string outputC = streamC.str();
    while(outputC.size() < 8) outputC = "0" + outputC;
    outputC = outputC.substr(6, 2) + outputC.substr(4, 2) + outputC.substr(2, 2) + outputC.substr(0, 2);
    
    string outputD = streamD.str();
    while(outputD.size() < 8) outputD = "0" + outputD;
    outputD = outputD.substr(6, 2) + outputD.substr(4, 2) + outputD.substr(2, 2) + outputD.substr(0, 2);
    
    return outputA + outputB + outputC + outputD;
}

string decrypt(string key, string ciphertext) {
    //initialization
    unsigned int p32 = 0xB7E15163;
    unsigned int q32 = 0x9E3779B9;
    int c = (key.size() * 4)/32;
    
    unsigned int l[c];
    for (int i = 0; i < key.size()/8; i++) {
        string temp = key.substr(8*i, 8);
        temp = temp.substr(6, 2) + temp.substr(4, 2) + temp.substr(2, 2) + temp.substr(0, 2);
        l[i] = stoul(temp, nullptr, 16);
    }
    
    //key schedule procedure
    unsigned int s[(2*20) + 3];
    s[0] = p32;
    for(int i = 1; i < (2*20) + 4; i++) {
        s[i] = s[i-1] + q32;
    }
    int a, b, i, j;
    a = b = i = j = 0;
    int v = 3 * max(c, (2*20) + 4);
    for(int iter = 1; iter < v + 1; iter++) {
        a = s[i] = leftRotate(s[i] + a + b, 3);
        b = l[j] = leftRotate(l[j] + a + b, a + b);
        i = (i + 1) % ((2*20)+4);
        j = (j + 1) % c;
    }
    
    string sA = ciphertext.substr(0, 8);
    string sB = ciphertext.substr(8, 8);
    string sC = ciphertext.substr(16, 8);
    string sD = ciphertext.substr(24, 8);
    
    /** 
    reverse so first byte of ciphertext is placed in least significant byte of A
    and last byte of ciphertext is placed in most significant byte of D
    **/
    
    sA = sA.substr(6, 2) + sA.substr(4, 2) + sA.substr(2, 2) + sA.substr(0, 2);
    sB = sB.substr(6, 2) + sB.substr(4, 2) + sB.substr(2, 2) + sB.substr(0, 2);
    sC = sC.substr(6, 2) + sC.substr(4, 2) + sC.substr(2, 2) + sC.substr(0, 2);
    sD = sD.substr(6, 2) + sD.substr(4, 2) + sD.substr(2, 2) + sD.substr(0, 2);
    
    unsigned int hA = stoul(sA, nullptr, 16);
    unsigned int hB = stoul(sB, nullptr, 16);
    unsigned int hC = stoul(sC, nullptr, 16);
    unsigned int hD = stoul(sD, nullptr, 16);
    
    //decryption procedure
    hC -= s[(2*20) + 3];
    hA -= s[(2*20) + 2];
    for(int iter = 20; iter > 0; --iter) {
        //(hA, hB, hC, hD) = (hD, hA, hB, hC)
        unsigned int temp = hD;
        hD = hC;
        hC = hB;
        hB = hA;
        hA = temp;
        
        unsigned int u = leftRotate(hD * (2 * hD + 1), 5);
        unsigned int t = leftRotate(hB * (2 * hB + 1), 5);
        hC = rightRotate(hC - s[(2 * iter) + 1], t) ^ u;
        hA = rightRotate(hA - s[2 * iter], u) ^ t;
    }
    hD -= s[1];
    hB -= s[0];
    
    stringstream streamA, streamB, streamC, streamD;
    streamA << hex << hA;
    streamB << hex << hB;
    streamC << hex << hC;
    streamD << hex << hD;
    
    string outputA = streamA.str();
    while(outputA.size() < 8) outputA = "0" + outputA;
    outputA = outputA.substr(6, 2) + outputA.substr(4, 2) + outputA.substr(2, 2) + outputA.substr(0, 2);
    
    string outputB = streamB.str();
    while(outputB.size() < 8) outputB = "0" + outputB;
    outputB = outputB.substr(6, 2) + outputB.substr(4, 2) + outputB.substr(2, 2) + outputB.substr(0, 2);
    
    string outputC = streamC.str();
    while(outputC.size() < 8) outputC ="0" + outputC;
    outputC = outputC.substr(6, 2) + outputC.substr(4, 2) + outputC.substr(2, 2) + outputC.substr(0, 2);
    
    string outputD = streamD.str();
    while(outputD.size() < 8) outputD = "0" + outputD;
    outputD = outputD.substr(6, 2) + outputD.substr(4, 2) + outputD.substr(2, 2) + outputD.substr(0, 2);
    
    return outputA + outputB + outputC + outputD;
}

int main(int argc, char ** argv) {
    
    string method, text, userkey;
    ifstream file(argv[1]);
    getline(file, method);
    getline(file, text);
    getline(file, userkey);
    
    text = text.substr(text.find(" ") + 1);
    userkey = userkey.substr(userkey.find(" ") + 1);
    
    for(int i = 0; i < text.size(); i++) {
        if(text[i] == ' ') text.erase(i, 1);
    }
    
    for(int i = 0; i < userkey.size(); i++) {
        if(userkey[i] == ' ') userkey.erase(i, 1);
    }
    
    string retVal;
    
    if(method == "Encryption") {
        string retVal = encrypt(userkey, text);
        ofstream out(argv[2]);
        out << "ciphertext: ";
        for(int i = 0; i < retVal.size(); i++) {
            if(i % 2 == 0) cout << " ";
            out << retVal[i];
        }
        out.close();
        
    } else if(method == "Decryption") {
        string retVal = decrypt(userkey, text);
        ofstream out(argv[2]);
        out << "plaintext: ";
        for(int i = 0; i < retVal.size(); i++) {
            if(i % 2 == 0) cout << " ";
            out << retVal[i];
        }
        out.close();
    } else {
        perror("Incorrect input file format.");
    }
    return 0;
}



