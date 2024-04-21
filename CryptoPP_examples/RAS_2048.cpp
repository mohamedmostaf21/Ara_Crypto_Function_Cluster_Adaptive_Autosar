// Include necessary header files for Crypto++ library
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include "cryptopp/hex.h"

// header files for standard C++ library
#include <iostream>
#include <string>

// namespaces 
using namespace CryptoPP;

// Function template to load a key from a file
template <typename Key>
const Key loadKey(const std::string& filename)
{
    Key key;
    CryptoPP::ByteQueue queue;
    CryptoPP::FileSource file(filename.c_str(), true);
    file.TransferTo(queue);
    queue.MessageEnd();

    key.Load(queue);
    return key;
}


int main(int argc, char** argv) 
{
    /**************************************************
    *                     plaintext                   *
    **************************************************/
    std::string plainText = "hi rsa";


    /**************************************************
    *   Load the private and public keys from files   *
    **************************************************/
    std::string fileContainsPRK = "private.key";
    std::string fileContainsPUK = "public.key";
    auto privateKey = loadKey<RSA::PrivateKey>(fileContainsPRK);
    auto publicKey = loadKey<RSA::PublicKey>(fileContainsPUK);


    /**************************************************
    *               random number generator           *
    **************************************************/
    // Initialize a random number generator
    AutoSeededRandomPool prng;


    /**************************************************
    *                    encryption                   *
    **************************************************/
    // Encrypt the plaintext using the public key
    std::string encrypted;
    RSAES_OAEP_SHA_Encryptor e(publicKey);
    StringSource( plainText,
                  true,
                  new PK_EncryptorFilter(prng, e, new StringSink(encrypted))
                );

    /***************************************************
    *                       Decryption                 *
    ***************************************************/
    // Decrypt the ciphertext using the private key
    std::string decrypted;
    RSAES_OAEP_SHA_Decryptor d(privateKey);
    StringSource( encrypted,
                  true,
                  new PK_DecryptorFilter(prng, d, new StringSink(decrypted))
                );


    /***************************************************
    *  print plaintext, ciphertext and recovered text  *
    ***************************************************/     
    // Create a HexEncoder object to output to console
    HexEncoder encoder(new FileSink(std::cout)); 

    // Print the plaintext string
    std::cout << "plain text: " << plainText << "\n";
     
    // Print the ciphertext in hexadecimal format
    std::cout << "cipher text: ";
    encoder.Put((const byte*)&encrypted[0], encrypted.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    // Print the recovered text
    std::cout << "recovered text: " << plainText << "\n";
}
