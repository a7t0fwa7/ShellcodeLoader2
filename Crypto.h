#pragma once
namespace Crypto
{
	void XORrecoder(unsigned char* Data, unsigned long Len_D, unsigned char key);
	void rc4_crypt(unsigned char* Data, unsigned long Len_D, unsigned char* key, unsigned long Len_k);
}
