#include <iostream>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include "cryptopp/files.h"

#define way 1

/*
    there are many elliptic curves used in cryptography
        - secp256k1    its equation is y^2 = x^3 + 7 mod(2^256 - 2^32 - 977) 
        - secp256r1
        - secp384r1
        - secp521r1 
        - Curve25519
        - ...
*/

int main()
{
    bool result;

    // define object represent private key for ECDSA 
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey myPrivateKey;

    // define object represent public key for ECDSA 
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

    
    /* 
    generate private key randomly    
        - first argument:  random number generator 
        - second argument: choose desired elliptic curve
    */
    CryptoPP::AutoSeededRandomPool prng;
    myPrivateKey.Initialize( prng, CryptoPP::ASN1::secp256k1() );
    
    // get private key value
    const CryptoPP::Integer& x = myPrivateKey.GetPrivateExponent();
    std::cout << "private Key: " << std::hex << x << std::endl;
    

    // fill the public key using private key object
    myPrivateKey.MakePublicKey( publicKey );
    /*
    result = publicKey.Validate( prng, 3 );
    if( !result ) { std::cout << "publicKey.Validate return false\n"; return 0; }
    */

    // get public key
    const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();
    const CryptoPP::Integer& qx = q.x;
    const CryptoPP::Integer& qy = q.y;    
    std::cout << "Public Key (qx): " << std::hex << qx << std::endl;
    std::cout << "Public Key (qy): " << std::hex << qy << std::endl;

    /* define object represent signer for ECDSA */
#if way == 1
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(myPrivateKey);
#elif way == 2
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer();
    signer.AccessKey().AccessGroupParameters() = myPrivateKey.GetGroupParameters();
#endif

    result = signer.AccessKey().Validate( prng, 3 );
    if( !result ) { std::cout << "signer.AccessKey return false\n"; return 0; }
    
    /* define object represent verifier for ECDSA */
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(publicKey);
    result = verifier.AccessKey().Validate(prng, 3);
    if( !result ) { std::cout << "verifier.AccessKey return false\n"; return 0; }

    // message 
    std::string message = "Do or do not. There is no try.";
    
    // Determine maximum size, allocate a string with the maximum size
    size_t siglen = signer.MaxSignatureLength();

    // signature = encryptionByPrivateKey(hash(message))
    std::string signature(siglen, 0x00);

    // Sign, and trim signature to actual size
    siglen = signer.SignMessage( prng,
                                 (const CryptoPP::byte*)message.data(),
                                 message.size(),
                                 (CryptoPP::byte*)signature.data()
                               );
    signature.resize(siglen);

    // Display the generated signature
    std::cout << "Generated Signature: " << std::endl;
    CryptoPP::StringSource( signature,
                            true,
                            new CryptoPP::HexEncoder( new CryptoPP::FileSink(std::cout))
                          );
   
   


    // Introduce an error in the signature
    if (!signature.empty()) {
        signature[0] ^= 0xFF; // Flip the first bit of the signature
    }

    result = verifier.VerifyMessage( (const CryptoPP::byte*)&message[0], message.size(), (const CryptoPP::byte*)&signature[0], signature.size() );
    if( !result ) 
    {
        std::cout << "Failed to verify signature on message" << std::endl;
    } else {
        std::cout << "\nAll good!\n" << std::endl;
    }


    
    std::cout << "hi ahmed\n";
}