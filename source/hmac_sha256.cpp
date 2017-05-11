#pragma once

#include "hmac_sha256.h"
#include <stdio.h>
#include <string.h>

hmac::hmac()
{
	si = new u8[BLOCK_LEN];
	so = new u8[BLOCK_LEN];
	digest = new u8[DIGEST_LEN];

	memset(si, 0x00, BLOCK_LEN * sizeof(u8));
	memset(so, 0x00, BLOCK_LEN * sizeof(u8));
	memset(digest, 0x00, DIGEST_LEN * sizeof(u8));
}

hmac::~hmac()
{
	delete si;
	delete so;
	delete digest;
}

void
hmac::hmac_init(u8 *key, int key_len)
{
	u8 i_pad = 0x36;
	u8 o_pad = 0x5c;

	if (key_len > BLOCK_LEN)
	{
		u8 temp_key[DIGEST_LEN];
		memset(temp_key, 0x00, DIGEST_LEN * sizeof(u8));
		SHA256_Encrpyt(key, key_len, temp_key);

		for (int i = 0; i < BLOCK_LEN; ++i)
		{
			if (i < DIGEST_LEN)
			{
				si[i] = temp_key[i] ^ i_pad;
				so[i] = temp_key[i] ^ o_pad;
			}
			else
			{
				si[i] = i_pad;
				so[i] = o_pad;
			}
		}
	}
	else
	{
		for (int i = 0; i < BLOCK_LEN; ++i)
		{
			if (i < key_len)
			{
				si[i] = key[i] ^ i_pad;
				so[i] = key[i] ^ o_pad;
			}
			else
			{
				si[i] = i_pad;
				so[i] = o_pad;
			}
		}
	}
}

void
hmac::hmac_run(u8 *key, int key_len, u8 *message, int msg_len)
{
	u8 *temp_msg;
	u8 *temp_sha_result;
	u8 *temp_outer_input;

	temp_msg = new u8[BLOCK_LEN + msg_len];
	temp_sha_result = new u8[DIGEST_LEN];
	temp_outer_input = new u8[BLOCK_LEN + DIGEST_LEN];

	memset(temp_msg, 0x00, (BLOCK_LEN + msg_len) * sizeof(u8));
	memset(temp_sha_result, 0x00, (DIGEST_LEN)* sizeof(u8));
	memset(temp_outer_input, 0x00, (BLOCK_LEN + DIGEST_LEN) * sizeof(u8));

	hmac_init(key, key_len);

	for (int i = 0; i < BLOCK_LEN + msg_len; ++i)
	{
		if (i < BLOCK_LEN)
			temp_msg[i] = si[i];
		else
			temp_msg[i] = message[i - BLOCK_LEN];
	}

	SHA256_Encrpyt(temp_msg, BLOCK_LEN + msg_len, temp_sha_result);

	for (int i = 0; i < BLOCK_LEN + DIGEST_LEN; ++i)
	{
		if (i < BLOCK_LEN)
			temp_outer_input[i] = so[i];

		else if ((i >= BLOCK_LEN) && (i < BLOCK_LEN + DIGEST_LEN))
			temp_outer_input[i] = temp_sha_result[i - BLOCK_LEN];

		else
			temp_outer_input[i] = 0x00;
	}

	SHA256_Encrpyt(temp_outer_input, BLOCK_LEN + DIGEST_LEN, digest);
}