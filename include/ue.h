#pragma once

#include "utils.h"
#include "nas_pdu.h"
#include "rrc_pdu.h"

class ue
{
public:
	ue();
	~ue();

	u8 *output;
	int output_len;

	u8 *ue_id;
	u8 *key;

	AV *av;
	u8 *ck;
	u8 *ik;
	u8 *ak;

	u8 *kasme;
	u8 *kenb;
	u8 *knas_int;
	u8 *knas_enc;
	u8 *krrc_int;
	u8 *krrc_enc;

	u8 int_nas_header;
	u8 enc_nas_header;

	u8 int_rrc_header;
	u8 enc_rrc_header;

	nas_pdu *nas;

	u8 *netMac;
	u8 *nas_message;
	int nas_message_len;
	u8 *xnas_mac;

	rrc_pdu *rrc;

	u8 *rrc_message;
	int rrc_message_len;
	u8 *mac_i;

	void init(float fo);
	void update(int type, u8 *input, int input_len);

	void ue_nas(u8 *input, int input_len);
	void ue_rrc(u8 *input, int input_len);

	void ue_AKA_run(u8 *key, u8 *netRand, u8 *netAUTN, bool reSyn);
	bool network_auth(u8 *res, u8 *xres);
	void auth_res_msg(u8 *res, int res_len);
	void sec_mode_complete();
	void rrc_sec_mode_complete();

private:

};