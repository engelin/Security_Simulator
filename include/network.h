#pragma once

#include "utils.h"
#include "k_table.h"
#include "nas_pdu.h"

class network
{
public:
	network();
	~network();

	u8 *output;
	int output_len;

	AV *av;
	u8 *ck;
	u8 *ik;
	u8 *ak;
	u8 *key;

	u8 *kasme;
	u8 *kenb;
	u8 *knas_int;
	u8 *knas_enc;

	nas_pdu *nas;

	u8 *nas_message;
	int nas_message_len;
	u8 *nas_mac;

	void init(u8 *rand_id, float fo);
	void update(u8 *input, int input_len);

	void hss_AKA_run(u8 *key, bool reSyn);
	void auth_req_msg(u8 *rand, u8 *autn, int autn_len);
	void sec_mode_command();

private:

};