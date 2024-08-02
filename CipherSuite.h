#ifndef CIPHERSUITE_H
#define CIPHERSUITE_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>

#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>
#include <cstddef> // for std::byte

class CipherSuite
{
public:
	Aes aes;
	std::vector<std::byte, 16> key iv;
	std::vector<std::byte, 16> authIn = {0};
	WC_RNG rng;
	static std::vector<std::byte, 16> pskKey;

	CipherSuite();
	void encryptAES(std::vector<std::byte> key, const std::string &input_path, const std::string &output_path);
	void decryptAES(std::vector<std::byte> key, const std::string &input_path, const std::string &output_path);
	void keyGenerator(ecc_key &key);
	static int PSKKeyGenerator(byte *pskKey, int keySize);
	void initializeCipherSuite();
};

#endif // CIPHERSUITE_H
