// header files for cryptopp library
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"

// header files for standard C++ library
#include <iostream>
#include <string>

// namespaces
using namespace CryptoPP;

/* 
in AES 
    key length (default): 16 byte
    key length (min)    : 16 byte
    key length (max)    : 32 byte
    block size          : 16 byte

CBC mode

           plaintext
               |
               |
               V
            -------
     IV --->| XOR |
            -------    
               |
               |
               V
            -------
     K  --->|  E  |
            ------- 
               |
               |
               V
           ciphertext  
*/

int main(int argc, char* argv[])
{
    /**************************************************
    *                     plaintext                   *
    **************************************************/
    std::string plain = "CBC Mode Test";


    /**************************************************
    *               random number generator           *
    **************************************************/
    // Initialize a random number generator
    AutoSeededRandomPool prng;


    /**************************************************
    *               key and IV generation             *
    **************************************************/
    // Generate a random key for AES encryption
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    // Generate a random IV for AES encryption
    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());


    /**************************************************
    *                    encryption                   *
    **************************************************/
    std::string cipher;
    try
    { 
        // Create an AES CBC encryption object and set the key and IV
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // Encrypt the plaintext and store the ciphertext
        StringSource s( plain,
                        true,
                        new StreamTransformationFilter( e, new StringSink(cipher))
                      );
    }
    catch(const Exception& e)
    {
        // Handle exceptions
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    
    /***************************************************
    *                       Decryption                 *
    ***************************************************/
    std::string recovered;
    try
    {
        // Create an AES CBC decryption object and set the key and IV
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        StringSource s( cipher,
                        true,
                        new StreamTransformationFilter(d, new StringSink(recovered)) 
                      ); 
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }


    /************************************************************
    *  print plaintext, key, IV, ciphertext and recovered text  *
    ************************************************************/ 
    // Print the plaintext string
    std::cout << "plain text: " << plain << std::endl;
    
    // Create a HexEncoder object to output to console
    HexEncoder encoder(new FileSink(std::cout)); 

    // Print the key in hexadecimal format
    std::cout << "key: ";
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    // Print the IV in hexadecimal format
    std::cout << "iv: ";
    encoder.Put(iv, iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    // Print the ciphertext in hexadecimal format
    std::cout << "cipher text: ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;
    
    // Print the recovered text
    std::cout << "recovered text: " << recovered << std::endl;

    return 0;
}