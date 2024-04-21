// header files for cryptopp library
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include "saveKey.h"


/*
The size of the ECDSA private key and public key generated 
depends on the elliptic curve being used.

the elliptic curve being used is secp256k1

For secp256k1 elliptic curve:

The size of the private key is 256 bits (32 bytes)
The size of the public key is 512 bits  (64 bytes) (since it consists of two 256-bit coordinates).
*/

int main(int argc, char** argv) 
{
  std::string publicKeyName = "ecdsa_public.key";    // Filename for the public key
  std::string privateKeyName = "ecdsa_private.key";  // Filename for the private key
  
  // Create an AutoSeededRandomPool object for random number generation
  CryptoPP::AutoSeededRandomPool prng;   

  // Generate private key
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey myPrivateKey;
  myPrivateKey.Initialize(prng, CryptoPP::ASN1::secp256k1());

  // Generate public key
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
  myPrivateKey.MakePublicKey(publicKey);

  SaveKey(publicKeyName, publicKey);    // Save the public key to a file
  SaveKey(privateKeyName, myPrivateKey);  // Save the private key to a file
}