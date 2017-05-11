#include "rrc_pdu.h"
#include "eea_eia.h"

rrc_pdu::rrc_pdu()
{
	rrc_pdu_len = 0;
	rrc_msg_type = 0x00;

	rrc_msg = new u8[10];
	rrc_pdu_msg = new u8[10];
	mac_i = new u8[NAS_MAC_LEN];
	xmac_i = new u8[NAS_MAC_LEN];

	memset(rrc_msg, 0x00, 10 * sizeof(u8));
	memset(rrc_pdu_msg, 0x00, (10) * sizeof(u8));
	memset(mac_i, 0x00, NAS_MAC_LEN * sizeof(u8));
	memset(xmac_i, 0x00, NAS_MAC_LEN * sizeof(u8));
}

rrc_pdu::~rrc_pdu()
{
	delete rrc_pdu_msg;
}

void
rrc_pdu::rrc_sec_enc(u8 pcdp_ns, u8 int_header, u8 enc_header, u8 *message, int msg_len, u8 *kint, u8 *kenc, u8 *count, u8 bearer, u8 direction)
{
	int i = 0;
	int j = 0;

	eea_eia *protection;
	protection = new eea_eia;

	u8 *temp_msg;
	temp_msg = new u8[msg_len + NAS_MAC_LEN];
	memset(temp_msg, 0x00, (msg_len + NAS_MAC_LEN) * sizeof(u8));

	rrc_pdu_msg[i] = pcdp_ns;
	temp_msg[j] = pcdp_ns;
	++i;
	++j;

	if (int_header == SEC_NULL)
	{
		memcpy(&temp_msg[j], message, msg_len * sizeof(u8));
	}
	else if (int_header == SEC_SNOW)
	{
		printf("not supported algorithm\n");
	}
	else if (int_header == SEC_AES)
	{
		memcpy(&temp_msg[j], message, msg_len * sizeof(u8));
		j += msg_len;

		protection->EIA2(kint, count, bearer, direction, temp_msg, msg_len + 1);
		memcpy(mac_i, protection->nas_mac, sizeof(mac_i));
		memcpy(&temp_msg[j], mac_i, NAS_MAC_LEN * sizeof(u8));
		j += NAS_MAC_LEN;
	}
	else if (int_header == SEC_ZUA)
	{
		printf("not supported algorithm\n");
	}
	else
	{
		printf("wrong type\n");
	}

	if (enc_header == SEC_NULL)
	{
		memcpy(&rrc_pdu_msg[i], &temp_msg[1], (j - 1) * sizeof(u8));
		i += j - 1;
	}
	else if (enc_header == SEC_SNOW)
	{
		printf("not supported algorithm\n");
	}
	else if (enc_header == SEC_AES)
	{
		protection->EEA2(kenc, count, bearer, direction, &temp_msg[1], j - 1);
		memcpy(&rrc_pdu_msg[i], protection->ciph, (j - 1) * sizeof(u8));
		i += j - 1;
	}
	else if (enc_header == SEC_ZUA)
	{
		printf("not supported algorithm\n");
	}
	else
	{
		printf("wrong type\n");
	}
	rrc_pdu_len = i;
}

void
rrc_pdu::rrc_sec_dec(u8 int_header, u8 enc_header, u8 *message, int msg_len, u8 *kint, u8 *kenc, u8 *count, u8 bearer, u8 direction)
{
	int i = 0;

	eea_eia *protection;
	protection = new eea_eia;

	u8 pcdp_sn = 0x00;
	u8 *temp_msg;
	temp_msg = new u8[msg_len];
	memset(temp_msg, 0x00, (msg_len) * sizeof(u8));

	rrc_msg_len = msg_len - NAS_MAC_LEN - 1;

	rrc_msg[i] = message[i];
	++i;
	
	if (enc_header == SEC_NULL)
	{
		memcpy(&rrc_msg[i], &message[i], rrc_msg_len * sizeof(u8));
		i += rrc_msg_len;
		memcpy(mac_i, &message[i], NAS_MAC_LEN * sizeof(u8));
	}
	else if (enc_header == SEC_SNOW)
	{
		printf("not supported algorithm\n");
	}
	else if (enc_header == SEC_AES)
	{
		protection->EEA2(kenc, count, bearer, direction, &message[i], msg_len - i);
		memcpy(temp_msg, protection->ciph, (msg_len - i) * sizeof(u8));
		
		memcpy(&rrc_msg[i], temp_msg, rrc_msg_len * sizeof(u8));
		i += rrc_msg_len;
		memcpy(mac_i, &temp_msg[i], NAS_MAC_LEN * sizeof(u8));
	}
	else if (enc_header == SEC_ZUA)
	{
		printf("not supported algorithm\n");
	}
	else
	{
		printf("wrong type\n");
	}

	if (int_header == SEC_NULL)
	{
		
	}
	else if (int_header == SEC_SNOW)
	{
		printf("not supported algorithm\n");
	}
	else if (int_header == SEC_AES)
	{
		protection->EIA2(kint, count, bearer, direction, rrc_msg, (rrc_msg_len +1) * sizeof(u8));
		memcpy(xmac_i, protection->nas_mac, NAS_MAC_LEN * sizeof(u8));

		if (!strncmp((char*)xmac_i, (char*)mac_i, NAS_MAC_LEN)) {
			printf("\n\t::::RRC pdu Integrity Check Success::::\n\n");
		}
		else {
			printf("\n\t::::RRC pdu Integrity Check Fail::::\n\n");
			return;
		}
	}
	else if (int_header == SEC_ZUA)
	{
		printf("not supported algorithm\n");
	}
	else
	{
		printf("wrong type\n");
	}
}

void
rrc_pdu::rrc_parsing(int dir, int msg_type, u8 *message, int msg_len)
{
	int i = 0;

	printf(" =============================RRC PDU=============================\n");
	if (dir == DL)
	{
		printf(" DL-");
		if (msg_type == SRB1)
		{
			printf("DCCH-MessageType-NB\n");
			if ((message[i] >> 7) == 0)
			{
				printf("\tmessage = c1 = SecurityModeCommand =\n");
				rrc_msg_type = SEC_MODE_COMMAND;
				++i;
				if ((message[i] >> 6) == 0)
				{
					printf("\t\trrc-TransactionIdentifier = 0\n");
					if ((message[i] >> 5) == 0)
					{
						printf("\t\tcriticalExtensions = c1 = securityModeCommand-r8 =\n");
						if ((message[i] >> 4) == 0)
						{
							printf("\t\tsecurityConfigSMC = \n");
							printf("\t\t\tcipheringAlgorithm = %02X\n", (message[i] & 0x0F));
							++i;
							printf("\t\t\tintegrityProtAlgorithm = %02X\n", (message[i] >> 4));
							printf(" =================================================================\n");
						}
					}
				}
			}
		}
		else
			printf("wrong type\n");
	}
	else if (dir == UL)
	{
		printf(" UL-");
		if (msg_type == SRB1)
		{
			printf("DCCH-MessageType-NB\n");
			if ((message[i] >> 7) == 0)
			{
				printf("\tmessage = c1 = SecurityModeComplete =\n");
				rrc_msg_type = SEC_MODE_COMPLETE;
				++i;
				if ((message[i] >> 6) == 0)
				{
					printf("\t\trrc-TransactionIdentifier = 0\n");
					if ((message[i] >> 5) == 0)
					{
						printf("\t\tcriticalExtensions = c1 = securityModeComplete-r8\n");
						printf(" =================================================================\n\n");
					}
				}
			}
		}
	}
	else
		printf("wrong type\n");
}