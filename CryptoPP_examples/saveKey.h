// header files for cryptopp library
#include <cryptopp/files.h>


/*
The template function is used to save a key to a file whose name is passed 
as argument and it can work with different types of keys, such as RSA keys, ECDSA keys, etc.
*/
template <typename Key>
void SaveKey(const std::string& filename, const Key& key) 
{
  // declares an object of ByteQueue (a queue of bytes used to store binary data)
  CryptoPP::ByteQueue queue; 

  // serializes the key and stores it in the ByteQueue
  key.Save(queue);

  /*
  creates an object of FileSink (for writting data to a file and It takes the filename as a parameter)
  
  If the file specified in CryptoPP::FileSink file(filename.c_str()) does not exist,
  the CryptoPP::FileSink constructor will create a new file with the given filename.

  If the file specified in CryptoPP::FileSink file(filename.c_str()) exists,
  the CryptoPP::FileSink constructor will clear file content.
  */
  CryptoPP::FileSink file(filename.c_str());
  
  // copies the contents of the ByteQueue (which now contains the serialized key) to the FileSink
  // effectively writing the key data to the file.
  queue.CopyTo(file);

  // signals the end of the message to the FileSink
  file.MessageEnd();
}