#include "nas_pdu.h"

nas_pdu::nas_pdu()
{
	nas_pdu_len = 0;

	nas_pdu_msg = new u8[10];
	memset(nas_pdu_msg, 0x00, (10) * sizeof(u8));

	net_rand = new u8[RAND_LENGTH];
	net_autn = new u8[AUTN_LENGTH];
	memset(net_rand, 0x00, RAND_LENGTH * sizeof(u8));
	memset(net_autn, 0x00, AUTN_LENGTH * sizeof(u8));
	net_autn_len = 0;

	ue_res = new u8[RES_LENGTH];
	memset(ue_res, 0x00, RES_LENGTH * sizeof(u8));
	ue_res_len = 0;

	nas_msg_type = 0x00;
}

nas_pdu::~nas_pdu()
{
	delete nas_mac;

	delete net_rand;
	delete net_autn;

	delete ue_res;
}

void
nas_pdu::nas_pdu_enc(u8 int_header, u8 proto_discrim, u8 *nas_msg, int msg_len)
{
	int i = 0;

	nas_pdu_msg[i] = ((int_header << 4) | proto_discrim);
	++i;
	memcpy(&nas_pdu_msg[i], nas_msg, msg_len);
	i += msg_len;

	nas_pdu_len = i;
}

void
nas_pdu::nas_pdu_enc(u8 int_header, u8 proto_discrim, u8 *nas_mac, u8 enc_header, u8 *nas_msg, int msg_len)
{
	int i = 0;

	nas_pdu_msg[i] = ((int_header << 4) | proto_discrim);
	++i;

	memcpy(&nas_pdu_msg[i], nas_mac, NAS_MAC_LEN * sizeof(u8));
	i += NAS_MAC_LEN;

	nas_sqn = 0x00;
	nas_pdu_msg[i] = nas_sqn;
	i += NAS_SQN_LEN;

	nas_pdu_msg[i] = ((enc_header << 4) | proto_discrim);
	++i;

	memcpy(&nas_pdu_msg[i], nas_msg, msg_len);
	i += msg_len;

	nas_pdu_len = i;
}

void
nas_pdu::nas_pdu_parsing(u8 *message, int msg_len)
{
	int i = 0;
	
	nas_msg_type = message[i];

	++i;
	printf("\tNAS EPS Mobility Management Message Type: ");
	if (nas_msg_type == AUTH_REQ)
	{
		printf("Authentication request\n");
		if (message[i] == 0x00)
		{
			printf("\t0000 .... = Spare half octet: 0\n");
			printf("\t.... 0... = Type of security context flag (TSG): Native security context\n");
			printf("\t.... .000 = NAS key set identifier: (0) ASME\n");
		}
		++i;
		memcpy(net_rand, &message[i], RAND_LENGTH * sizeof(u8));
		i += RAND_LENGTH;
		printf("\tRAND VALUE: ");
		for (int n = 0; n < RAND_LENGTH; ++n)
			printf("%02X", net_rand[n]);
		printf("\n");

		printf("\tAuthentication token parameter\n");
		net_autn_len = message[i];
		printf("\t\tLength: %d\n", net_autn_len);
		++i;

		memcpy(net_autn, &message[i], AUTN_LENGTH * sizeof(u8));
		printf("\t\tAUTN VALUE: ");
		for (int n = 0; n < AUTN_LENGTH; ++n)
			printf("%02X", net_autn[n]);
		printf("\n");

		i += AUTN_LENGTH;
	}
	else if (nas_msg_type == AUTH_RES)
	{
		printf("Authentication response\n");
		printf("\tAuthentication response parameter\n");
		ue_res_len = message[i];
		printf("\t\tLength: %d\n", ue_res_len);
		++i;

		memcpy(ue_res, &message[i], RES_LENGTH * sizeof(u8));
		printf("\t\tRES: ");
		for (int n = 0; n < RES_LENGTH; n++)
			printf("%02X", ue_res[n]);
		printf("\n");
		i += RES_LENGTH;
	}
	else if (nas_msg_type == SEC_MODE_COMMAND)
	{
		printf("Security mode command\n");
		u8 cip_type = 0xF0;
		u8 int_type = 0x0F;

		cip_type = ((cip_type & message[i]) >> 4);
		int_type &= message[i];
		++i;

		printf("\t0... .... = Spare bit(s)\n");
		if (cip_type == 0x01)
			printf("\t.001 .... = Type of ciphering algorithm: EPS encryption algorithm 128-EEA1\n");
		else if (cip_type == 0x02)
			printf("\t.010 .... = Type of ciphering algorithm: EPS encryption algorithm 128-EEA2\n");
		else if (cip_type == 0x03)
			printf("\t.011 .... = Type of ciphering algorithm: EPS encryption algorithm 128-EEA3\n");
		else
		{
			printf("wrong type\n");
			return;
		}

		printf("\t.... 0... = Spare bit(s)\n");
		if (int_type == 0x01)
			printf("\t.... .001 = Type of integrity algorithm: EPS integrity algorithm 128-EIA1\n");
		else if (int_type == 0x02)
			printf("\t.... .010 = Type of integrity algorithm: EPS integrity algorithm 128-EIA2\n");
		else if (int_type == 0x03)
			printf("\t.... .011 = Type of integrity algorithm: EPS integrity algorithm 128-EIA3\n");
		else
		{
			printf("wrong type\n");
			return;
		}

		if (message[i] == 0x00)
		{
			printf("\t0000 .... = Spare half octet: 0\n");
			printf("\t.... 0... = Type of security context flag (TSG): Native security context\n");
			printf("\t.... .001 = NAS key set identifier: (1) ASME\n");
		}
		++i;

		printf("\tUE security capabiltiy - Replayed UE security capabilities\n");
		int cap_len;
		cap_len = message[i];
		++i;
		printf("\t\tLength: %d\n", cap_len);

		u8 cap_enc;
		cap_enc = message[i];
		++i;
		if (cap_enc == 0xA0)
		{
			printf("\t\t1... .... = EEA0: Supported\n");
			printf("\t\t.0.. .... = EEA1: Not Supported\n");
			printf("\t\t..1. .... = 128-EEA2: Supported\n");
			printf("\t\t...0 .... = EEA3: Not Supported\n");
			printf("\t\t.... 0... = EEA4: Not Supported\n");
			printf("\t\t.... .0.. = EEA5: Not Supported\n");
			printf("\t\t.... ..0. = EEA6: Not Supported\n");
			printf("\t\t.... ...0 = EEA7: Not Supported\n");
		}
		else
		{
		}

		u8 cap_int;
		cap_int = message[i];
		++i;
		if (cap_int == 0xA0)
		{
			printf("\t\t1... .... = EIA0: Supported\n");
			printf("\t\t.0.. .... = EIA1: Not Supported\n");
			printf("\t\t..1. .... = 128-EIA2: Supported\n");
			printf("\t\t...0 .... = EIA3: Not Supported\n");
			printf("\t\t.... 0... = EIA4: Not Supported\n");
			printf("\t\t.... .0.. = EIA5: Not Supported\n");
			printf("\t\t.... ..0. = EIA6: Not Supported\n");
			printf("\t\t.... ...0 = EIA7: Not Supported\n");
		}
		else
		{
		}
	}
	else if (nas_msg_type == SEC_MODE_COMPLETE)
	{
		printf("Security mode complete\n");
	}
	else
	{
		printf("wrong type\n");
	}
	printf(" =================================================================\n");
	printf("\n\n");
}