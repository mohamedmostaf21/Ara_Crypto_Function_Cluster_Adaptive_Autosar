#ifndef LOAD_KEY
#define LOAD_KEY


// Include necessary header files for Crypto++ library
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include "cryptopp/hex.h"
#include <iostream>
#include <string>

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

#endif