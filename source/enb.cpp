#include "enb.h"

#include <stdio.h>
#include <string.h>

enb::enb()
{
	output = new u8[MAX_LEN];

	kenb = new u8[DIGEST_LEN];
	krrc_int = new u8[DIGEST_LEN / 2];
	krrc_enc = new u8[DIGEST_LEN / 2];

	rrc = new rrc_pdu;

	mac_i = new u8[DIGEST_LEN / 2];

	output_len = 0;
	rrc_message_len = 0;
}

enb::~enb()
{
	delete output;

	delete kenb;
	delete krrc_int;
	delete krrc_enc;

	delete rrc;

	delete mac_i;
}

void
enb::init(u8 *k)
{
	kdf *key_derivation;
	key_derivation = new kdf;

	u8 pcdp_ns = 0x05;
	u8 count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	u8 bearer = 0x15;

	memset(kenb, 0x00, DIGEST_LEN * sizeof(u8));
	memset(krrc_int, 0x00, (DIGEST_LEN / 2) * sizeof(u8));
	memset(krrc_enc, 0x00, (DIGEST_LEN / 2) * sizeof(u8));
	
	memcpy(kenb, k, DIGEST_LEN * sizeof(u8));
	key_derivation->ksec_df(kenb, SEC_AES, RRC_INT_ALG);
	memcpy(krrc_int, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));

	memset(key_derivation->derived_key, 0x00, DIGEST_LEN * sizeof(u8));
	key_derivation->ksec_df(kenb, SEC_AES, RRC_ENC_ALG);
	memcpy(krrc_enc, &key_derivation->derived_key[DIGEST_LEN / 2], (DIGEST_LEN / 2) * sizeof(u8));

	sec_mode_command(SEC_AES, SEC_NULL);

	rrc->rrc_sec_enc(pcdp_ns, SEC_AES, SEC_NULL, rrc_message, rrc_message_len, krrc_int, krrc_enc, count, bearer, DL);

	output_len = rrc->rrc_pdu_len;
	memcpy(output, rrc->rrc_pdu_msg, output_len * sizeof(u8));
}

void
enb::update(u8 *input, int input_len)
{
	int i = 0;

	rrc_pdu *rrc;
	rrc = new rrc_pdu;

	u8 count[4] = { 0x39, 0x8a, 0x59, 0xb4 };
	u8 bearer = 0x15;

	rrc->rrc_sec_dec(SEC_AES, SEC_NULL, input, input_len, krrc_int, krrc_enc, count, bearer, UL);
	rrc->rrc_parsing(UL, SRB1, rrc->rrc_msg, rrc->rrc_msg_len);


}

void
enb::sec_mode_command(u8 intID, u8 encID)
{
	int i = 0;
	rrc_message = new u8[SEC_MODE_COMMAND_LEN];
	memset(rrc_message, 0x00, SEC_MODE_COMMAND_LEN * sizeof(u8));

	u8 DL_DCCH_Message_NB = 0;
	u8 rrc_TransactionIdentifier = 0;
	u8 criticalExtensions = 0;
	u8 SecurityConfigSMC = 0;

	rrc_message[i] = (DL_DCCH_Message_NB << 7) | (rrc_TransactionIdentifier << 6) | (criticalExtensions << 5) | (SecurityConfigSMC << 4);
	rrc_message[i] |= encID;
	++i;
	rrc_message[i] = (intID << 4);
	++i;
	
	rrc_message_len = i;
}