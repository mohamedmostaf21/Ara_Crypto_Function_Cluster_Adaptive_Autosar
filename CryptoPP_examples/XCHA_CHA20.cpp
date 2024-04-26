#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/chacha.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"

#include <iostream>
#include <string>

int main()
{
    using namespace CryptoPP;

    AutoSeededRandomPool prng;
    std::string plain("My Plaintext!! My Dear plaintext!!"), cipher, recover;

    SecByteBlock key(32), iv(8);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());



    // Encryption object
    ChaCha::Encryption enc;    
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    // Perform the encryption
    cipher.resize(plain.size());
    enc.ProcessData((byte*)&cipher[0], (const byte*)plain.data(), plain.size());


    std::cout << "Plain: " << plain << std::endl;

    ChaCha::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    // Perform the decryption
    recover.resize(cipher.size());
    dec.ProcessData((byte*)&recover[0], (const byte*)cipher.data(), cipher.size());


    std::cout << "Recovered: " << recover << std::endl;

    return 0;
}