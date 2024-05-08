#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include <span>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>


using ReadOnlyMemRegion = std::span<const std::uint8_t>;

class HashFunctionCtx 
{
public:
    virtual CryptoPP::SHA256 GetDigestService() const = 0;
    
    // virtual void Start(const CryptoPP::SecByteBlock& iv) = 0;
    virtual void Start() = 0;    
    virtual void Start(ReadOnlyMemRegion iv) = 0;


    //virtual void Update(const CryptoPP::SecByteBlock& in) = 0;
    virtual void Update(ReadOnlyMemRegion in) = 0;


    //virtual CryptoPP::SecByteBlock Finish() = 0;
    virtual std::vector<std::uint8_t> Finish() = 0;


    //virtual CryptoPP::SecByteBlock GetDigest(size_t offset = 0) const = 0;
    virtual std::vector<std::uint8_t> GetDigest(size_t offset = 0) const = 0;
};

class MyHashFunctionCtx : public HashFunctionCtx {
private:
    CryptoPP::SHA256 hash;
    CryptoPP::SecByteBlock digest;

public:
    CryptoPP::SHA256 GetDigestService() const override {
        return hash;
    }
    
    void Start() override {
        hash.Restart();
    }
    
    /*
    void Start(const CryptoPP::SecByteBlock& iv) override {
        hash.Update(iv, iv.size());
    }
    */

    void Start(ReadOnlyMemRegion iv) override {
        hash.Update(iv.data(), iv.size());
    }

    /*
    void Update(const CryptoPP::SecByteBlock& in) override {
        hash.Update(in, in.size());
    }
    */

    void Update(ReadOnlyMemRegion in) override {
        hash.Update(in.data(), in.size());
    }

    /*
    CryptoPP::SecByteBlock Finish() override {
        digest.resize(hash.DigestSize());
        hash.Final(digest);
        return digest;
    }
    */

   std::vector<std::uint8_t> Finish() override 
   {
        digest.resize(hash.DigestSize());
        hash.Final(digest);
        return std::vector<std::uint8_t>(digest.begin(), digest.end());
    }

    /*
    CryptoPP::SecByteBlock GetDigest(size_t offset = 0) const override {
        return digest;
    }
    */

    std::vector<std::uint8_t> GetDigest(size_t offset = 0) const override {
        return std::vector<std::uint8_t>(digest.begin(), digest.end());
    }

};

int main() 
{
    MyHashFunctionCtx myHashCtx;
    
    myHashCtx.Start();
    
    /*
    CryptoPP::SecByteBlock data(reinterpret_cast<const std::uint8_t*>("ahmed mahmoud"), 13);
    CryptoPP::SecByteBlock hashValue = myHashCtx.Finish();
    myHashCtx.Update(data);
    */

    std::string str = "ahmed mahmoud";
    ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    myHashCtx.Update(instr);
    
    
    std::vector<uint8_t> hashValue = myHashCtx.Finish();

    std::vector<uint8_t> hashValue2 = myHashCtx.GetDigest();


    /***************************************************
    *                  print digest                    *
    ***************************************************/ 
    // Convert digest to hexadecimal string
    std::stringstream ss;
    for (const auto& byte : hashValue) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    // Print the hexadecimal digest
    std::cout << ss.str() << std::endl;


    /***************************************************
    *                  print digest                    *
    ***************************************************/ 
    // Convert digest to hexadecimal string
    std::stringstream ss2;
    for (const auto& byte : hashValue2) {
        ss2 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    // Print the hexadecimal digest
    std::cout << ss2.str() << std::endl;

    return 0;
}