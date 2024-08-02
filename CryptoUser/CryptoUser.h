#ifndef CRYPTOUSER_H
#define CRYPTOUSER_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>

#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <cstddef> // for std::byte

#include "../CipherSuite.h"

class CryptoUser
{
	ecc_key priv, pub;

public:
	byte keySession[AES_256_KEY_SIZE];
	word32 keySessionSz = AES_256_KEY_SIZE;
	CipherSuite cipher_suite = CipherSuite();
	;
	static byte pskKey[16];

	CryptoUser();

	void initializeCryptoUser();
	ecc_key getPub() const;
	void setKeySession(ecc_key userPub);
	void encryptMessage(std::vector<byte> key, const std::string &input_path, const std::string &output_path);
	void decryptMessage(std::vector<byte> key, const std::string &input_path, const std::string &output_path);
};

#endif // CRYPTOUSER_H