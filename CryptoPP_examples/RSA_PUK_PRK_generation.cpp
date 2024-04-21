// header files for cryptopp library
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include "saveKey.h"


int main(int argc, char** argv) {
  std::string publicKeyName = "rsa_public.key";    // Filename for the public key
  std::string privateKeyName = "rsa_private.key";  // Filename for the private key
  size_t keyLength = 2048;                     // Specify the key length here

  CryptoPP::InvertibleRSAFunction parameters;  // Create RSA parameters object
  CryptoPP::AutoSeededRandomPool prng;   // Create an AutoSeededRandomPool object for random number generation
  parameters.GenerateRandomWithKeySize(prng, keyLength);  // Generate random RSA parameters with the specified key length

  CryptoPP::RSA::PrivateKey privateKey(parameters);  // Create RSA private key using the generated parameters
  CryptoPP::RSA::PublicKey publicKey(parameters);    // Create RSA public key using the generated parameters

  SaveKey(publicKeyName, publicKey);    // Save the public key to a file
  SaveKey(privateKeyName, privateKey);  // Save the private key to a file
}