#include "addRandGen.h"

#include <string.h>
#include <stdio.h>

addRandGen::addRandGen()
{
	add_rand = new u8[ADD_RAND_LENGTH];
	memset(add_rand, 0x00, sizeof(add_rand));
}

addRandGen::~addRandGen()
{
	delete add_rand;
}

void
addRandGen::additional_rand_gen(float data)
{
	u8 *hex_data;
	u8 *hashed_data;

	hex_data = new u8[HEX_DATA_LENGTH];
	hashed_data = new u8[HASH_LENGTH];

	memset(hex_data, 0x00, HEX_DATA_LENGTH * sizeof(u8));
	memset(hashed_data, 0x00, HASH_LENGTH * sizeof(u8));

	memcpy(hex_data, float_to_hex(data), FLOAT_DATA_LENGTH);

	SHA256_Encrpyt(hex_data, sizeof(hex_data), hashed_data);

	for (int i = 0; i < ADD_RAND_LENGTH; ++i) {
		add_rand[i] = hashed_data[i * 4] ^ hashed_data[i * 4 + 1] ^ hashed_data[i * 4 + 2] ^ hashed_data[i * 4 + 3];
	}
}

u8*
addRandGen::float_to_hex(float in)
{
	union
	{
		float in;
		u8 out[sizeof(float)];
	} conv;

	conv.in = in;

	return conv.out;
}