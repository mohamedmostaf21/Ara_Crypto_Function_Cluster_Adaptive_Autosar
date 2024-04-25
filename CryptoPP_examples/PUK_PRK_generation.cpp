// header files for cryptopp library
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"

// header files for standard C++ library
#include <string>

// namespaces
using namespace CryptoPP;


// Function to save a key to a file
template <typename Key>
void SaveKey(const std::string& filename, const Key& key) {
  ByteQueue queue;
  key.Save(queue);
  FileSink file(filename.c_str());
  
  queue.CopyTo(file);
  file.MessageEnd();
}

int main(int argc, char** argv) {
  std::string publicKeyName = "public.key";    // Filename for the public key
  std::string privateKeyName = "private.key";  // Filename for the private key
  size_t keyLength = 2048;                     // Specify the key length here

  AutoSeededRandomPool prng;   // Create an AutoSeededRandomPool object for random number generation

  InvertibleRSAFunction parameters;  // Create RSA parameters object
  parameters.GenerateRandomWithKeySize(prng, keyLength);  // Generate random RSA parameters with the specified key length

  RSA::PrivateKey privateKey(parameters);  // Create RSA private key using the generated parameters
  RSA::PublicKey publicKey(parameters);    // Create RSA public key using the generated parameters

  SaveKey(publicKeyName, publicKey);    // Save the public key to a file
  SaveKey(privateKeyName, privateKey);  // Save the private key to a file
}