#include "eea_eia.h"
#include <stdio.h>
#include <string.h>

eea_eia::eea_eia()
{
	nas_mac = new u8[AES_BLOCK_LEN];
	mac_i = new u8[AES_BLOCK_LEN];
	memset(nas_mac, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(mac_i, 0x00, AES_BLOCK_LEN * sizeof(u8));
}

eea_eia::~eea_eia()
{
	delete ciph;
	delete nas_mac;
	delete mac_i;
}

void
eea_eia::aes_ctr(u8 *key, u8 *input, int key_stream_len, u8 *key_stream)
{
	int cnt = key_stream_len;
	int len = key_stream_len;
	u8 *counter;
	u8 *temp;
	u8 *key_stream_temp;

	counter = new u8[AES_BLOCK_LEN];
	temp = new u8[AES_BLOCK_LEN];
	key_stream_temp = new u8[key_stream_len];

	memset(counter, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(temp, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(key_stream_temp, 0x00, key_stream_len * sizeof(u8));

	memcpy(counter, input, AES_BLOCK_LEN * sizeof(u8));

	RijndaelKeySchedule(key);

	while (cnt > 0) {
		RijndaelEncrypt(counter, temp);
		len = (cnt < AES_BLOCK_LEN) ? cnt : AES_BLOCK_LEN;

		for (int i = 0; i < len; ++i)
			key_stream_temp[i] ^= temp[i];

		memcpy(&key_stream[key_stream_len - cnt], key_stream_temp, key_stream_len * sizeof(u8));

		key_stream_temp += len;
		cnt -= len;
		for (int i = AES_BLOCK_LEN - 1; i >= 0; i--) {
			counter[i]++;
			if (counter[i])
				break;
		}
	}
}

void
leftshift_onebit(u8 *input, u8 *output)
{
	u8 overflow = 0;

	for (int i = 15; i >= 0; --i)
	{
		output[i] = input[i] << 1;
		output[i] |= overflow;
		overflow = (input[i] & 0x80) ? 1 : 0;
	}
}

void
generate_subkey(u8 *key, u8 *K1, u8 *K2)
{
	u8 Rb[AES_BLOCK_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };

	u8 L[AES_BLOCK_LEN];
	u8 Z[AES_BLOCK_LEN];
	u8 temp[AES_BLOCK_LEN];

	memset(L, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(Z, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(temp, 0x00, AES_BLOCK_LEN * sizeof(u8));

	RijndaelKeySchedule(key);
	RijndaelEncrypt(Z, L);

	if ((L[0] & 0x80) == 0)
		leftshift_onebit(L, K1);
	else
	{
		leftshift_onebit(L, temp);
		for (int i = 0; i < AES_BLOCK_LEN; ++i)
			K1[i] = temp[i] ^ Rb[i];
	}

	if ((K1[0] & 0x80) == 0)
		leftshift_onebit(K1, K2);
	else
	{
		memset(temp, 0x00, AES_BLOCK_LEN * sizeof(u8));
		leftshift_onebit(K1, temp);
		for (int i = 0; i < AES_BLOCK_LEN; ++i)
			K2[i] = temp[i] ^ Rb[i];
	}
}

void
eea_eia::aes_cmac(u8 *key, u8 *input, int len, u8 *cmac)
{
	u8 K1[AES_BLOCK_LEN], K2[AES_BLOCK_LEN];
	u8 M_last[AES_BLOCK_LEN], padded[AES_BLOCK_LEN];

	memset(K1, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(K2, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(M_last, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(padded, 0x00, AES_BLOCK_LEN * sizeof(u8));

	bool block_completed;
	int block_num;
	block_num = (len + 15) / AES_BLOCK_LEN;

	generate_subkey(key, K1, K2);

	if (block_num == 0)
	{
		++block_num;
		block_completed = 0;
	}
	else
	{
		if (len % 16 == 0)
			block_completed = 1;
		else
			block_completed = 0;
	}

	if (block_completed)
	{
		for (int i = 0; i < AES_BLOCK_LEN; ++i)
			M_last[i] = input[AES_BLOCK_LEN * (block_num - 1) + i] ^ K1[i];
	}
	else
	{
		for (int i = 0; i < AES_BLOCK_LEN; ++i)
		{
			if (i < len % AES_BLOCK_LEN)
				padded[i] = input[AES_BLOCK_LEN * (block_num - 1) + i];
			else if (i == len % AES_BLOCK_LEN)
				padded[i] = 0x80;
			else
				padded[i] = 0x00;
		}

		for (int i = 0; i < AES_BLOCK_LEN; ++i)
			M_last[i] = padded[i] ^ K2[i];
	}

	u8 temp0[AES_BLOCK_LEN], temp1[AES_BLOCK_LEN];
	memset(temp0, 0x00, AES_BLOCK_LEN * sizeof(u8));
	memset(temp1, 0x00, AES_BLOCK_LEN * sizeof(u8));

	for (int i = 0; i < block_num - 1; ++i)
	{
		for (int j = 0; j < AES_BLOCK_LEN; ++j)
			temp1[j] = input[AES_BLOCK_LEN * i + j] ^ temp0[j];

		RijndaelKeySchedule(key);
		RijndaelEncrypt(temp1, temp0);
	}

	for (int i = 0; i < AES_BLOCK_LEN; ++i)
		temp1[i] = temp0[i] ^ M_last[i];

	RijndaelKeySchedule(key);
	RijndaelEncrypt(temp1, cmac);
}

void
eea_eia::EEA2(u8 *key, u8 *count, u8 bearer, u8 direction, u8 *plain, int bit_len)
{
	int byte_len = bit_len / 8 + 1;

	ciph = new u8[byte_len];
	memset(ciph, 0x00, byte_len * sizeof(u8));

	u8 *key_stream;
	key_stream = new u8[byte_len];
	memset(key_stream, 0x00, byte_len * sizeof(u8));

	u8 *input;
	int input_len = AES_BLOCK_LEN;

	input = new u8[AES_BLOCK_LEN];
	memset(input, 0x00, AES_BLOCK_LEN * sizeof(u8));

	u8 temp = 0x00;
	temp = (bearer << 3) | (direction << 2);

	memcpy(input, count, NAS_COUNT_LEN * sizeof(u8));
	memcpy(&input[NAS_COUNT_LEN], &temp, sizeof(u8));

	aes_ctr(key, input, byte_len, key_stream);

	for (int i = 0; i < byte_len; ++i)
		ciph[i] = plain[i] ^ key_stream[i];
}

void
eea_eia::EIA2(u8 *key, u8 *count, u8 bearer, u8 direction, u8 *message, int len)
{
	u8 *input;
	int input_len = NAS_COUNT_LEN + PAD_BEARER_LEN + len;

	input = new u8[NAS_COUNT_LEN + PAD_BEARER_LEN + len];
	memset(input, 0x00, (NAS_COUNT_LEN + PAD_BEARER_LEN + len) * sizeof(u8));

	u8 temp = 0x00;
	temp = (bearer << 3) | (direction << 2);

	memcpy(input, count, NAS_COUNT_LEN * sizeof(u8));
	memcpy(&input[NAS_COUNT_LEN], &temp, sizeof(u8));
	memcpy(&input[NAS_COUNT_LEN + PAD_BEARER_LEN], message, len * sizeof(u8));

	aes_cmac(key, input, input_len, nas_mac);
}