#pragma once

#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sha.h"

class rrc_pdu
{
public:
	rrc_pdu();
	~rrc_pdu();

	u8 *rrc_pdu_msg;
	int rrc_pdu_len;

	u8 *rrc_msg;
	int rrc_msg_len;

	u8 *mac_i;
	u8 *xmac_i;
	u8 rrc_sqn;
	u8 enc_header;
	u8 int_header;
	u8 rrc_msg_type;

	void rrc_sec_enc(u8 pcdp_ns, u8 int_header, u8 enc_header, u8 *message, int msg_len, u8 *kint, u8 *kenc, u8 *count, u8 bearer, u8 direction);
	void rrc_sec_dec(u8 int_header, u8 enc_header, u8 *message, int msg_len, u8 *kint, u8 *kenc, u8 *count, u8 bearer, u8 direction);
	void rrc_parsing(int dir, int msg_type, u8 *message, int msg_len);

private:

};