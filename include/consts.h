#pragma once

#define MAX_LEN 256
#define NAS 0
#define RRC 1

#define CK_LENGTH 16
#define IK_LENGTH 16
#define AK_LENGTH 6
#define MAC_LENGTH 8
#define SQN_LENGTH 6
#define AMF_LENGTH 2
#define RAND_LENGTH 16
#define AUTN_LENGTH 16
#define RES_LENGTH 8

#define UE_ID_LEN 8
#define KEY_LEN 16
#define ADD_RAND_LENGTH 8
#define EXTERN_DATA_NUM 3
#define FLOAT_DATA_LENGTH sizeof(float)
#define HEX_DATA_LENGTH EXTERN_DATA_NUM * FLOAT_DATA_LENGTH
#define HASH_LENGTH 32

#define RESYNC 0

#define ADD_RAND_ONOFF 1

#define KASME_STR_LEN 14
#define KENB_STR_LEN 7
#define SNID_LEN 3
#define NAS_COUNT_LEN 4
#define ALG_DIST_LEN 1
#define ALG_ID_LEN 1

#define NAS_ENC_ALG 0x01
#define NAS_INT_ALG 0x02
#define RRC_ENC_ALG 0x03
#define RRC_INT_ALG 0x04
#define UP_ENC_ALG 0x05

#define AUTH_REQ 0x52
#define AUTH_RES 0x53
#define SEC_MODE_COMMAND 0x5D
#define SEC_MODE_COMPLETE 0x5E

#define SEC_NULL 0x00
#define SEC_SNOW 0x01
#define SEC_AES 0x02
#define SEC_ZUA 0x03

#define PROTO_DES 0x07

#define NAS_MAC_LEN 4
#define NAS_MAC_ADDR 1
#define NAS_SQN_LEN 1
#define INT_NAS_MSG_ADDR 7

#define AUTH_REQ_LEN 2+RAND_LENGTH+1+AUTN_LENGTH
#define AUTH_RES_LEN 2+RES_LENGTH
#define SEC_MODE_COMMAND_LEN 6
#define SEC_MODE_COMPLETE_LEN 1

#define ENC_HEADER_NULL 0
#define ENC_HEADER_AES 2
#define GENERAL_MSG_LEN 1+MAC_LENGTH+SQN_LENGTH

#define DL 0x00
#define UL 0x01
#define SRB1 1
#define RRC_TRANS_ID 0
#define CRITIC_EXT 1
