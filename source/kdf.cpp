#include "kdf.h"
#include <stdio.h>
#include <string.h>

kdf::kdf()
{
	derived_key = new u8[DIGEST_LEN];
	memset(derived_key, 0x00, DIGEST_LEN * sizeof(u8));
}

kdf::~kdf()
{
	delete string;
	delete derived_key;
}

int
kdf::str_cat(u8 fc, u8 *p0, int l0)
{
	int i = 0;
	int str_len = l0 + 3;

	string = new u8[str_len];
	memset(string, 0x00, str_len * sizeof(u8));

	string[i] = fc; ++i;
	memcpy(&string[i], p0, l0 * sizeof(u8));
	i += l0 + 1;
	string[i] = l0; ++i;

	return str_len;
}

int
kdf::str_cat(u8 fc, u8 *p0, int l0, u8 *p1, int l1)
{
	int i = 0;
	str_len = l0 + l1 + 5;

	string = new u8[str_len];
	memset(string, 0x00, str_len * sizeof(u8));

	string[i] = fc; ++i;
	memcpy(&string[i], p0, l0 * sizeof(u8));
	i += l0 + 1;
	string[i] = l0; ++i;
	memcpy(&string[i], p1, l1 * sizeof(u8));
	i += l1 + 1;
	string[i] = l1; ++i;

	return str_len;
}

void
kdf::kasme_df(u8 *ck, u8 *ik, u8 *sqn)
{
	hmac *kdf_hmac;
	kdf_hmac = new hmac;

	u8 *temp_key;
	temp_key = new u8[CK_LENGTH + IK_LENGTH];
	memset(temp_key, 0x00, (CK_LENGTH + IK_LENGTH) * sizeof(u8));

	u8 snid[SNID_LEN] = { 0x00, 0x01, 0x10 };

	for (int i = 0; i < CK_LENGTH + IK_LENGTH; ++i)
	{
		if (i < CK_LENGTH)
			temp_key[i] = ck[i];
		else
			temp_key[i] = ik[i - CK_LENGTH];
	}

	int str_len = str_cat(0x10, snid, SNID_LEN, sqn, SQN_LENGTH);

	kdf_hmac->hmac_run(temp_key, CK_LENGTH + IK_LENGTH, string, str_len);
	memcpy(derived_key, kdf_hmac->digest, DIGEST_LEN * sizeof(u8));
}

void
kdf::kenb_df(u8 *Kasme, u8 *nas_count)
{
	hmac *kdf_hmac;
	kdf_hmac = new hmac;

	int str_len = str_cat(0x11, nas_count, NAS_COUNT_LEN);

	kdf_hmac->hmac_run(Kasme, DIGEST_LEN, string, str_len);
	memcpy(derived_key, kdf_hmac->digest, DIGEST_LEN * sizeof(u8));
}

void
kdf::ksec_df(u8 *k, u8 alg_id, u8 alg_dist)
{
	hmac *kdf_hmac;
	kdf_hmac = new hmac;

	int i = 0;
	int str_len = ALG_DIST_LEN + ALG_ID_LEN + 5;

	string = new u8[str_len];
	memset(string, 0x00, str_len * sizeof(u8));

	string[i] = 0x15; ++i;
	string[i] = alg_dist; i += 2;
	string[i] = ALG_DIST_LEN; ++i;
	string[i] = alg_id; i += 2;
	string[i] = ALG_ID_LEN;

	kdf_hmac->hmac_run(k, DIGEST_LEN, string, str_len);
	memcpy(derived_key, kdf_hmac->digest, DIGEST_LEN * sizeof(u8));
}