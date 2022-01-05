#include "Crypto.h"
#include <stdio.h>
#include <string.h>


void Crypto::XORrecoder(unsigned char* Data, unsigned long Len_D, unsigned char key)
{
	for (size_t i = 0; i < Len_D; i++)
	{
		Data[i] ^= key;
	}
}

void __forceinline rc4_init(unsigned char* s, unsigned char* key, unsigned long Len_k)
{
	int i = 0, j = 0;
	char k[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++) {
		s[i] = i;
		k[i] = key[i % Len_k];
	}
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
}

void Crypto::rc4_crypt(unsigned char* Data, unsigned long Len_D, unsigned char* key, unsigned long Len_k)
{
	unsigned char s[256];
	rc4_init(s, key, Len_k);
	int i = 0, j = 0, t = 0;
	unsigned long k = 0;
	unsigned char tmp;
	for (k = 0; k < Len_D; k++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		Data[k] = Data[k] ^ s[t];
	}
}
