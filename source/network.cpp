#include "network.h"
#include "generator.h"
#include "addRandGen.h"
#include "kdf.h"
#include "eea_eia.h"
#include "milenage.h"

#include <stdio.h>
#include <string.h>

network::network()
{
	output = new u8[MAX_LEN];

	av = new AV;
	ck = new u8[CK_LENGTH];
	ik = new u8[IK_LENGTH];
	ak = new u8[AK_LENGTH];

	kasme = new u8[DIGEST_LEN];
	kenb = new u8[DIGEST_LEN];
	knas_int = new u8[DIGEST_LEN / 2];
	knas_enc = new u8[DIGEST_LEN / 2];

	nas = new nas_pdu();

	nas_mac = new u8[NAS_MAC_LEN];
	memset(nas_mac, 0x00, NAS_MAC_LEN * sizeof(u8));

	output_len = 0;
	nas_message_len = 0;
}

network::~network()
{
	delete output;

	delete av;
	delete ck;
	delete ik;
	delete ak;

	delete kasme;
	delete kenb;
	delete knas_int;
	delete knas_enc;

	delete nas;

	delete nas_mac;
}

void
network::init(u8 *rand_id, float fo)
{
	addRandGen *addGen;
	k_table *kTable;
	addGen = new addRandGen;
	kTable = new k_table;

	kdf *key_derivation;
	key_derivation = new kdf;

	u8 ue_id[UE_ID_LEN];
	memset(ue_id, 0x00, UE_ID_LEN * sizeof(u8));

	memset(output, 0x00, MAX_LEN * sizeof(u8));

	memset(av, 0x00, sizeof(AV));
	memset(ck, 0x00, CK_LENGTH * sizeof(u8));
	memset(ik, 0x00, IK_LENGTH * sizeof(u8));
	memset(ak, 0x00, AK_LENGTH * sizeof(u8));

	memset(kasme, 0x00, DIGEST_LEN * sizeof(u8));
	memset(kenb, 0x00, DIGEST_LEN * sizeof(u8));
	memset(knas_int, 0x00, (DIGEST_LEN / 2) * sizeof(u8));
	memset(knas_enc, 0x00, (DIGEST_LEN / 2) * sizeof(u8));

	addGen->additional_rand_gen(fo);

	for (int i = 0; i < ADD_RAND_LENGTH; ++i)
	{
		ue_id[i] = rand_id[i] ^ addGen->add_rand[i];
	}
	kTable->key_search(ue_id);

	hss_AKA_run(kTable->key, RESYNC);

	key_derivation->ksec_df(kasme, SEC_AES, NAS_INT_ALG);
	memcpy(knas_int, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));
	memset(key_derivation->derived_key, 0x00, DIGEST_LEN * sizeof(u8));
	key_derivation->ksec_df(kasme, SEC_AES, NAS_ENC_ALG);
	memcpy(knas_enc, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));

	auth_req_msg(av->rand, (u8 *)&av->autn, AUTN_LENGTH);
	nas->nas_pdu_enc(SEC_NULL, PROTO_DES, nas_message, nas_message_len);

	memcpy(output, nas->nas_pdu_msg, nas->nas_pdu_len * sizeof(u8));
	output_len = nas->nas_pdu_len;
}

void
network::update(u8 *input, int input_len)
{
	int i = 0;
	u8 int_header = 0xF0;
	u8 enc_header = 0xF0;
	u8 proto_discrim = 0x0F;
	u8 *xnas_mac;
	u8 nas_sqn;
	u8 *nas_msg;
	u8 *enc_nas_msg;
	int nas_msg_len;
	int enc_nas_msg_len = 0;

	eea_eia *protection;
	protection = new eea_eia;

	nas_sqn = 0;
	nas_msg_len = 0;
	nas_msg = new u8[nas_msg_len];
	enc_nas_msg = new u8[enc_nas_msg_len];
	xnas_mac = new u8[NAS_MAC_LEN];
	memset(xnas_mac, 0x00, NAS_MAC_LEN * sizeof(u8));
	memset(nas_msg, 0x00, (nas_msg_len)* sizeof(u8));
	memset(enc_nas_msg, 0x00, (enc_nas_msg_len)* sizeof(u8));

	u8 count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	u8 bearer = 0x15;

	int_header = ((int_header & input[i]) >> 4);
	proto_discrim &= input[i];
	++i;

	printf(" =============================NAS PDU=============================\n");
	if (int_header == SEC_NULL)
	{
		printf("\t0000 .... = Security header type: Plain NAS message, not security protected\n");
		if (proto_discrim == PROTO_DES) printf("\t.... 0111 = Protocol discriminator: EPS mobility management messages\n");
	}
	else
	{
		if (proto_discrim == PROTO_DES) printf("\t.... 0111 = Protocol discriminator: EPS mobility management messages\n");
		if (int_header == SEC_SNOW)
		{
			printf("\t0001 .... = Security header type: Integrity protected with EIA1\n");
		}
		else if (int_header == SEC_AES)
		{
			printf("\t0010 .... = Security header type: Integrity protected with EIA2\n");
		}
		else if (int_header == SEC_ZUA)
		{
			printf("\t0011 .... = Security header type: Integrity protected with EIA3\n");
		}
		else
		{
			printf("\twrong type\n");
			return;
		}
		
		memcpy(xnas_mac, &input[i], NAS_MAC_LEN * sizeof(u8));
		i += NAS_MAC_LEN;
		printf("\tNAS MAC: ");
		for (int n = 0; n < NAS_MAC_LEN; ++n)
			printf("%02X", xnas_mac[n]);
		printf("\n");

		nas_msg_len = input_len - INT_NAS_MSG_ADDR;
		memcpy(nas_msg, &input[i + 2], (nas_msg_len)* sizeof(u8));

		protection->EIA2(knas_int, count, bearer, UL, nas_msg, nas_msg_len);

		if (!strncmp((char*)xnas_mac, (char*)protection->nas_mac, sizeof(nas_mac))) {
			printf("\n\t::::Integrity Check Success::::\n\n");
		}
		else {
			printf("\n\t::::Integrity Check Fail::::\n\n");
			return;
		}

		nas_sqn = input[i];
		i += NAS_SQN_LEN;
		printf("\tNAS Sequence Number: %02X\n", nas_sqn);

		enc_header = ((enc_header & input[i]) >> 4);
		proto_discrim &= input[i];
		++i;

		if (enc_header == SEC_NULL)
		{
			printf("\t0000 .... = Security header type: Plain NAS message, not security protected\n");
			if (proto_discrim == PROTO_DES) printf("\t.... 0111 = Protocol discriminator: EPS mobility management messages\n");
		}
		else
		{
			if (proto_discrim == PROTO_DES) printf("\t.... 0111 = Protocol discriminator: EPS mobility management messages\n");
			if (enc_header == SEC_SNOW)
			{
				printf("\t0001 .... = Security header type: Encrypto protected with EEA1\n");
			}
			else if (enc_header == SEC_AES)
			{
				printf("\t0010 .... = Security header type: Encrypto protected with EEA2\n");
				enc_nas_msg_len = input_len - i;
				memcpy(nas_msg, &input[i], (enc_nas_msg_len)* sizeof(u8));

				protection->EEA2(knas_enc, count, bearer, UL, nas_msg, nas_msg_len);
				memcpy(enc_nas_msg, protection->ciph, enc_nas_msg_len * sizeof(u8));
			}
			else if (enc_header == SEC_ZUA)
			{
				printf("\t0011 .... = Security header type: Encrypto protected with EEA3\n");
			}
			else
			{
				printf("\twrong type\n");
				return;
			}
		}
	}

	nas_msg_len = input_len - i;
	memcpy(nas_msg, &input[i], (nas_msg_len)* sizeof(u8));

	if ((enc_header == SEC_SNOW) || (enc_header == SEC_AES) || (enc_header == SEC_ZUA))
		memcpy(nas_msg, enc_nas_msg, enc_nas_msg_len * sizeof(u8));

	nas->nas_pdu_parsing(nas_msg, nas_msg_len);

	if (nas->nas_msg_type == AUTH_RES)
	{
		if (!strncmp((char*)nas->ue_res, (char*)av->res, RES_LENGTH * sizeof(u8)))
		{
			printf("\t:::::::::::UE AUTHENTICATION SUCCESS:::::::::::\n");
			printf("\t\tAuthentication Response Parameter\n");
			printf("\t\tRES\t");
			for (int i = 0; i < RES_LENGTH * sizeof(u8); ++i)
				printf("%02X ", nas->ue_res[i]);

			printf("\n\t\tXRES\t");
			for (int i = 0; i < RES_LENGTH * sizeof(u8); ++i)
				printf("%02X ", av->res[i]);
			printf("\n\n\n");
		}
		else
		{
			printf("\t:::::::::::UE AUTHENTICATION FAIL:::::::::::\n");
			printf("\t\tAuthentication Response Parameter\n");
			printf("\t\tRES\t");
			for (int i = 0; i < RES_LENGTH * sizeof(u8); ++i)
				printf("%02X ", nas->ue_res[i]);

			printf("\n\t\tXRES\t");
			for (int i = 0; i < RES_LENGTH * sizeof(u8); ++i)
				printf("%02X ", av	->res[i]);
			printf("\n\n");

			return;
		}

		sec_mode_command();
		nas->nas_pdu_enc(SEC_AES, PROTO_DES, nas_mac, SEC_NULL, nas_message, nas_message_len);

		output_len = nas->nas_pdu_len;
		memcpy(output, nas->nas_pdu_msg, output_len * sizeof(u8));
	}
	else if (nas->nas_msg_type == SEC_MODE_COMPLETE)
	{
	}
	else
	{
		printf("wrong type\n");
	}
}

void
network::hss_AKA_run(u8 *key, bool reSyn)
{
	kdf *key_derivation;
	AUTN *autn;
	generator *gen;

	key_derivation = new kdf;
	autn = new AUTN();
	gen = new generator();

	memset(autn, 0x00, sizeof(AUTN));
	memset(gen, 0x00, sizeof(gen));

	u8 AMF[2] = { 0xb9, 0xb9 };
	gen->gen_init();

	memcpy(&autn->amf, AMF, sizeof(autn->amf));
	memcpy(&av->rand, gen->rand, sizeof(av->rand));
	memcpy(&autn->sqn, &gen->sqn, SQN_LENGTH * sizeof(u8));

	if (!reSyn) {

		f1(key, av->rand, autn->sqn, autn->amf, autn->mac);
		f2345(key, av->rand, av->res, ck, ik, ak);

		key_derivation->kasme_df(ck, ik, autn->sqn);
		memcpy(kasme, key_derivation->derived_key, DIGEST_LEN * sizeof(u8));
		memset(key_derivation->derived_key, 0x00, DIGEST_LEN * sizeof(u8));

		for (int i = 0; i < SQN_LENGTH; ++i) {
			autn->sqn[i] ^= ak[i];
		}
	}
	else {

		f1star(key, av->rand, autn->sqn, autn->amf, autn->mac);
		f2345(key, av->rand, av->res, ck, ik, ak);
		memset(ak, 0x00, 6 * sizeof(u8));
		f5star(key, av->rand, ak);

		key_derivation->kasme_df(ck, ik, autn->sqn);
		memcpy(kasme, key_derivation->derived_key, DIGEST_LEN * sizeof(u8));
		memset(key_derivation->derived_key, 0x00, DIGEST_LEN * sizeof(u8));

		for (int i = 0; i < SQN_LENGTH; ++i) {
			autn->sqn[i] ^= ak[i];
		}
	}
	memcpy(&av->autn, autn, sizeof(AUTN));

	u8 nas_count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	key_derivation->kenb_df(kasme, nas_count);
	memcpy(kenb, key_derivation->derived_key, DIGEST_LEN * sizeof(u8));
}

void
network::auth_req_msg(u8 *rand, u8 *autn, int autn_len)
{
	int i = 0;

	nas_message = new u8[AUTH_REQ_LEN];
	memset(nas_message, 0x00, AUTH_REQ_LEN * sizeof(u8));

	nas_message[i] |= AUTH_REQ;
	++i;
	nas_message[i] |= 0x00;
	++i;
	memcpy(&nas_message[i], rand, RAND_LENGTH * sizeof(u8));
	i += RAND_LENGTH;
	nas_message[i] = autn_len;
	++i;
	memcpy(&nas_message[i], autn, autn_len * sizeof(u8));
	i += autn_len;

	nas_message_len = i;
}

void
network::sec_mode_command()
{
	int i = 0;
	memset(nas_mac, 0x00, (DIGEST_LEN / 2) * sizeof(u8));

	nas_message = new u8[SEC_MODE_COMMAND_LEN];
	memset(nas_message, 0x00, SEC_MODE_COMMAND_LEN * sizeof(u8));

	kdf *key_derivation;
	key_derivation = new kdf;

	eea_eia *EIA;
	EIA = new eea_eia;

	key_derivation->ksec_df(kasme, SEC_AES, NAS_INT_ALG);
	memcpy(knas_int, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));

	memset(key_derivation->derived_key, 0x00, DIGEST_LEN * sizeof(u8));
	key_derivation->ksec_df(kasme, SEC_AES, NAS_ENC_ALG);
	memcpy(knas_enc, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));

	nas_message[i] |= SEC_MODE_COMMAND;
	++i;
	nas_message[i] |= 0x22;
	++i;
	nas_message[i] |= 0x01;
	++i;
	nas_message[i] |= 0x02;
	++i;
	nas_message[i] |= 0xA0;
	++i;
	nas_message[i] |= 0xA0;
	++i;

	nas_message_len = i;

	u8 count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	u8 bearer = 0x15;

	EIA->EIA2(knas_int, count, bearer, DL, nas_message, nas_message_len);
	memcpy(nas_mac, EIA->nas_mac, sizeof(nas_mac));
}