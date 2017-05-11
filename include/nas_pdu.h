#pragma once

#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sha.h"

class nas_pdu
{
public:
	nas_pdu();
	~nas_pdu();

	u8 *nas_pdu_msg;
	int nas_pdu_len;

	u8 *nas_msg;
	int nas_msg_len;

	u8 *nas_mac;
	u8 nas_sqn;
	u8 enc_header;
	u8 int_header;
	u8 nas_msg_type;

	u8 *net_rand;
	u8 *net_autn;
	int net_autn_len;

	u8 *ue_res;
	int ue_res_len;

	void nas_pdu_enc(u8 int_header, u8 proto_discrim, u8 *nas_msg, int msg_len);
	void nas_pdu_enc(u8 int_header, u8 proto_discrim, u8 *nas_mac, u8 enc_header, u8 *nas_msg, int msg_len);
	void nas_pdu_parsing(u8 *message, int msg_len);

private:

};