#include "ue.h"

#include "k_table.h"
#include "addRandGen.h"
#include "kdf.h"
#include "eea_eia.h"
#include "milenage.h"

#include <stdio.h>
#include <string.h>

ue::ue()
{
	output = new u8[MAX_LEN];

	ue_id = new u8[UE_ID_LEN];
	key = new u8[KEY_LEN];

	av = new AV;
	ck = new u8[CK_LENGTH];
	ik = new u8[IK_LENGTH];
	ak = new u8[AK_LENGTH];

	kasme = new u8[DIGEST_LEN];
	kenb = new u8[DIGEST_LEN];
	knas_int = new u8[DIGEST_LEN / 2];
	knas_enc = new u8[DIGEST_LEN / 2];
	krrc_int = new u8[DIGEST_LEN / 2];
	krrc_enc = new u8[DIGEST_LEN / 2];

	nas = new nas_pdu;
	rrc = new rrc_pdu;

	netMac = new u8[MAC_LENGTH];

	xnas_mac = new u8[DIGEST_LEN / 2];
	mac_i = new u8[DIGEST_LEN / 2];

	output_len = 0;
	nas_message_len = 0;
}

ue::~ue()
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
	delete krrc_int;
	delete krrc_enc;

	delete nas;
	delete rrc;

	delete netMac;

	delete xnas_mac;
	delete mac_i;
}

void
ue::init(float fo)
{
	kdf *key_derivation;
	key_derivation = new kdf;
	addRandGen *addGen;

	addGen = new addRandGen();

	memset(output, 0x00, MAX_LEN * sizeof(u8));

	memset(ue_id, 0x00, UE_ID_LEN * sizeof(u8));
	memset(key, 0x00, KEY_LEN * sizeof(u8));

	memset(av, 0x00, sizeof(AV));
	memset(ck, 0x00, CK_LENGTH * sizeof(u8));
	memset(ik, 0x00, IK_LENGTH * sizeof(u8));
	memset(ak, 0x00, AK_LENGTH * sizeof(u8));

	memset(kasme, 0x00, DIGEST_LEN * sizeof(u8));
	memset(kenb, 0x00, DIGEST_LEN * sizeof(u8));
	memset(knas_int, 0x00, (DIGEST_LEN / 2) * sizeof(u8));
	memset(knas_enc, 0x00, (DIGEST_LEN / 2) * sizeof(u8));
	memset(krrc_int, 0x00, (DIGEST_LEN / 2) * sizeof(u8));
	memset(krrc_enc, 0x00, (DIGEST_LEN / 2) * sizeof(u8));

	memset(netMac, 0x00, MAC_LENGTH * sizeof(u8));
	memset(mac_i, 0x00, NAS_MAC_LEN * sizeof(u8));

	int_nas_header = 0x00;
	enc_nas_header = 0x00;
	int_rrc_header = 0x00;
	enc_rrc_header = 0x00;

	u8 UE_ID[UE_ID_LEN] = { 0x45, 0x00, 0x05, 0x01, 0x23, 0x45, 0x67, 0x89 };

	for (int i = 0; i < UE_ID_LEN; ++i)
	{
		ue_id[i] = UE_ID[i];
	}

	addGen->additional_rand_gen(fo);

	for (int i = 0; i < ADD_RAND_LENGTH; ++i)
	{
		output[i] = ue_id[i] ^ addGen->add_rand[i];
	}
	output_len = ADD_RAND_LENGTH;
}

void
ue::update(int type, u8 *input, int input_len)
{
	if (type == NAS)
	{
		ue_nas(input, input_len);
	}
	else if (type == RRC)
	{
		ue_rrc(input, input_len);
	}
	else
	{
		printf("wrong type\n");
	}
}

void
ue::ue_nas(u8 *input, int input_len)
{
	int i = 0;
	int_nas_header = 0xF0;
	enc_nas_header = 0xF0;
	u8 proto_discrim = 0x0F;
	u8 *nas_mac;
	u8 nas_sqn;
	u8 *nas_msg;
	u8 *enc_nas_msg;
	int nas_msg_len;
	int enc_nas_msg_len = 0;

	k_table *kTable;
	kTable = new k_table;
	kdf *key_derivation;
	key_derivation = new kdf;
	eea_eia *protection;
	protection = new eea_eia;

	nas_sqn = 0;
	nas_msg_len = 0;
	nas_mac = new u8[NAS_MAC_LEN];
	nas_msg = new u8[nas_msg_len];
	enc_nas_msg = new u8[enc_nas_msg_len];
	memset(nas_msg, 0x00, (nas_msg_len)* sizeof(u8));
	memset(nas_mac, 0x00, NAS_MAC_LEN * sizeof(u8));
	memset(enc_nas_msg, 0x00, (enc_nas_msg_len)* sizeof(u8));

	u8 count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	u8 bearer = 0x15;

	int_nas_header = ((int_nas_header & input[i]) >> 4);
	proto_discrim &= input[i];
	++i;

	printf(" =============================NAS PDU=============================\n");
	if (int_nas_header == SEC_NULL)
	{
		printf("\t0000 .... = Security header type: Plain NAS message, not security protected\n");
		if (proto_discrim == PROTO_DES) printf("\t.... 0111 = Protocol discriminator: EPS mobility management messages\n");
	}
	else
	{
		if (proto_discrim == PROTO_DES) printf("\t.... 0111 = Protocol discriminator: EPS mobility management messages\n");
		if (int_nas_header == SEC_SNOW)
		{
			printf("\t0001 .... = Security header type: Integrity protected with EIA1\n");
		}
		else if (int_nas_header == SEC_AES)
		{
			printf("\t0010 .... = Security header type: Integrity protected with EIA2\n");
		}
		else if (int_nas_header == SEC_ZUA)
		{
			printf("\t0011 .... = Security header type: Integrity protected with EIA3\n");
		}
		else
		{
			printf("\twrong type\n");
			return;
		}

		key_derivation->ksec_df(kasme, SEC_AES, NAS_INT_ALG);
		memcpy(knas_int, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));

		memcpy(nas_mac, &input[i], NAS_MAC_LEN * sizeof(u8));
		i += NAS_MAC_LEN;
		printf("\tNAS MAC: ");
		for (int n = 0; n < NAS_MAC_LEN; ++n)
			printf("%02X", nas_mac[n]);
		printf("\n");

		nas_msg_len = input_len - INT_NAS_MSG_ADDR;
		memcpy(nas_msg, &input[i + 2], (nas_msg_len)* sizeof(u8));

		protection->EIA2(knas_int, count, bearer, DL, nas_msg, nas_msg_len);

		if (!strncmp((char*)nas_mac, (char*)protection->nas_mac, sizeof(nas_mac))) {
			printf("\n\t::::Integrity Check Success::::\n\n");
		}
		else {
			printf("\n\t::::Integrity Check Fail::::\n\n");
			return;
		}

		nas_sqn = input[i];
		i += NAS_SQN_LEN;
		printf("\tNAS Sequence Number: %02X\n", nas_sqn);

		enc_nas_header = ((enc_nas_header & input[i]) >> 4);
		proto_discrim &= input[i];
		++i;

		memset(key_derivation->derived_key, 0x00, DIGEST_LEN * sizeof(u8));
		key_derivation->ksec_df(kasme, SEC_AES, NAS_ENC_ALG);
		memcpy(knas_enc, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));

		if (enc_nas_header == SEC_NULL)
		{
			printf("\t0000 .... = Security header type: Plain NAS message, not security protected\n");
			if (proto_discrim == PROTO_DES) printf("\t.... 0111 = Protocol discriminator: EPS mobility management messages\n");
		}
		else
		{
			if (proto_discrim == PROTO_DES) printf("\t.... 0111 = Protocol discriminator: EPS mobility management messages\n");
			if (enc_nas_header == SEC_SNOW)
			{
				printf("\t0001 .... = Security header type: Encrypto protected with EEA1\n");
			}
			else if (enc_nas_header == SEC_AES)
			{
				printf("\t0010 .... = Security header type: Encrypto protected with EEA2\n");
				enc_nas_msg_len = input_len - i;
				memcpy(nas_msg, &input[i], (enc_nas_msg_len)* sizeof(u8));

				protection->EEA2(knas_enc, count, bearer, DL, nas_msg, nas_msg_len);
				memcpy(enc_nas_msg, protection->ciph, enc_nas_msg_len * sizeof(u8));
			}
			else if (enc_nas_header == SEC_ZUA)
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

	if ((enc_nas_header == SEC_SNOW) || (enc_nas_header == SEC_AES) || (enc_nas_header == SEC_ZUA))
		memcpy(nas_msg, enc_nas_msg, enc_nas_msg_len * sizeof(u8));

	nas->nas_pdu_parsing(nas_msg, nas_msg_len);

	if (nas->nas_msg_type == AUTH_REQ)
	{
		kTable->key_search(ue_id);
		ue_AKA_run(kTable->key, nas->net_rand, nas->net_autn, RESYNC);

		if (!strncmp((char*)netMac, (char*)av->autn.mac, MAC_LENGTH * sizeof(u8)))
		{
			printf("\t:::::::::::NETWORK AUTHENTICATION SUCCESS:::::::::::\n");
			printf("\t\tAutentication Vector Parameter\n");
			printf("\t\tMAC\t");
			for (int i = 0; i < MAC_LENGTH; ++i)
				printf("%02X ", netMac[i]);

			printf("\n\t\tXMAC\t");
			for (int i = 0; i < MAC_LENGTH; ++i)
				printf("%02X ", av->autn.mac[i]);
			printf("\n\n\n");
		}
		else
		{
			printf("\t:::::::::::NETWORK AUTHENTICATION SUCCESS:::::::::::\n");
			printf("\t\tCause: MAC fail (20)\n\n");

			printf("\t\tAutentication Vector Parameter\n");
			printf("\t\tMAC\t");
			for (int i = 0; i < MAC_LENGTH; ++i)
				printf("%02X ", netMac[i]);

			printf("\nXMAC\t");
			for (int i = 0; i < MAC_LENGTH; ++i)
				printf("%02X ", av->autn.mac[i]);
			printf("\n\n\n");

			return;
		}

		auth_res_msg(av->res, RES_LENGTH);
		nas->nas_pdu_enc(SEC_NULL, PROTO_DES, nas_message, nas_message_len);

		output_len = nas->nas_pdu_len;
		memcpy(output, nas->nas_pdu_msg, output_len * sizeof(u8));
	}
	else if (nas->nas_msg_type == SEC_MODE_COMMAND)
	{
		sec_mode_complete();
		nas->nas_pdu_enc(SEC_AES, PROTO_DES, xnas_mac, SEC_AES, nas_message, nas_message_len);

		output_len = nas->nas_pdu_len;
		memcpy(output, nas->nas_pdu_msg, output_len * sizeof(u8));
	}
	else
	{
		printf("wrong type\n");
	}
}

void
ue::ue_rrc(u8 *input, int input_len)
{
	int i = 0;

	rrc_pdu *rrc;
	rrc = new rrc_pdu;

	u8 count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	u8 bearer = 0x15;

	rrc->rrc_sec_dec(SEC_AES, SEC_NULL, input, input_len, krrc_int, krrc_enc, count, bearer, DL);
	rrc->rrc_parsing(DL, SRB1, rrc->rrc_msg, rrc->rrc_msg_len);

	if (rrc->rrc_msg_type == SEC_MODE_COMMAND)
	{
		u8 pcdp_ns = 0x05;
		rrc_sec_mode_complete();

		rrc->rrc_sec_enc(pcdp_ns, SEC_AES, SEC_NULL, rrc_message, rrc_message_len, krrc_int, krrc_enc, count, bearer, UL);

		output_len = rrc->rrc_pdu_len;
		memcpy(output, rrc->rrc_pdu_msg, output_len * sizeof(u8));
	}
	else
	{
		printf("wrong type\n");
	}
}

void
ue::ue_AKA_run(u8 *key, u8 *netRand, u8 *netAUTN, bool reSyn)
{
	AUTN *autn;

	autn = new AUTN;

	memset(autn, 0x00, sizeof(AUTN));

	memcpy(&av->rand, netRand, sizeof(av->rand)); //rand generator로 수정해야됨

	memcpy(autn->sqn, &netAUTN[0], SQN_LENGTH * sizeof(u8));
	memcpy(autn->amf, &netAUTN[SQN_LENGTH], AMF_LENGTH * sizeof(u8));
	memcpy(autn->mac, &netAUTN[SQN_LENGTH + 2], MAC_LENGTH * sizeof(u8));

	memcpy(netMac, autn->mac, MAC_LENGTH * sizeof(u8));

	if (!reSyn) {

		f2345(key, av->rand, av->res, ck, ik, ak);

		for (int i = 0; i < SQN_LENGTH; ++i) {
			autn->sqn[i] = autn->sqn[i] ^ ak[i];
		}
		f1(key, av->rand, autn->sqn, autn->amf, autn->mac);
	}
	else {

		f2345(key, av->rand, av->res, ck, ik, ak);
		memset(ak, 0x00, 6 * sizeof(u8));
		f5star(key, av->rand, ak);

		for (int i = 0; i < SQN_LENGTH; ++i) {
			autn->sqn[i] = autn->sqn[i] ^ ak[i];
		}
		f1star(key, av->rand, autn->sqn, autn->amf, autn->mac);
	}
	memcpy(&av->autn, autn, sizeof(AUTN));

	kdf *key_derivation;
	key_derivation = new kdf;

	key_derivation->kasme_df(ck, ik, autn->sqn);
	memcpy(kasme, key_derivation->derived_key, DIGEST_LEN * sizeof(u8));
	memset(key_derivation->derived_key, 0x00, DIGEST_LEN * sizeof(u8));

	u8 nas_count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	key_derivation->kenb_df(kasme, nas_count);
	memcpy(kenb, key_derivation->derived_key, DIGEST_LEN * sizeof(u8));

	key_derivation->ksec_df(kenb, SEC_AES, RRC_INT_ALG);
	memcpy(krrc_int, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));

	memset(key_derivation->derived_key, 0x00, DIGEST_LEN * sizeof(u8));
	key_derivation->ksec_df(kenb, SEC_AES, RRC_ENC_ALG);
	memcpy(krrc_enc, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));
}

void
ue::auth_res_msg(u8 *res, int res_len)
{
	int i = 0;

	nas_message = new u8[RES_LENGTH];
	memset(nas_message, 0x00, RES_LENGTH * sizeof(u8));

	nas_message[i] |= AUTH_RES;
	++i;
	nas_message[i] = res_len;
	++i;
	memcpy(&nas_message[i], res, RES_LENGTH * sizeof(u8));
	i += RES_LENGTH;

	nas_message_len = i;
}

void
ue::sec_mode_complete()
{
	eea_eia *protection;
	protection = new eea_eia;

	u8 count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	u8 bearer = 0x15;
	u8 direction = 0x01;

	int i = 0;

	nas_message = new u8[SEC_MODE_COMPLETE_LEN];
	memset(nas_message, 0x00, SEC_MODE_COMPLETE_LEN * sizeof(u8));

	nas_message[i] |= SEC_MODE_COMPLETE;
	++i;

	nas_message_len = i;

	protection->EEA2(knas_enc, count, bearer, direction, nas_message, nas_message_len);
	memset(nas_message, 0x00, nas_message_len * sizeof(u8));
	memcpy(nas_message, protection->ciph, nas_message_len * sizeof(u8));

	protection->EIA2(knas_int, count, bearer, direction, nas_message, nas_message_len);
	memcpy(xnas_mac, protection->nas_mac, NAS_MAC_LEN * sizeof(u8));
}

void
ue::rrc_sec_mode_complete()
{
	int i = 0;

	rrc_message = new u8[SEC_MODE_COMPLETE_LEN];
	memset(rrc_message, 0x00, SEC_MODE_COMPLETE_LEN * sizeof(u8));

	u8 SecurityModeComplete = 0;
	u8 RRC_TransactionIdentifier = 0;
	u8 criticalExtension = 0;

	rrc_message[i] = (SecurityModeComplete << 3) | (RRC_TransactionIdentifier << 2) | (criticalExtension << 1);
	++i;

	rrc_message_len = i;
}