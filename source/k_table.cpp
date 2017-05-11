#include "k_table.h"


k_table::k_table()
{
	key = new u8[KEY_LEN];
	memset(key, 0x00, KEY_LEN * sizeof(u8));
}

k_table::~k_table()
{
	delete key;
}

void
k_table::key_search(u8 *ue_id)
{
	u8 UE_ID[UE_ID_LEN] = { 0x45, 0x00, 0x05, 0x01, 0x23, 0x45, 0x67, 0x89 };

	if (!strncmp((char*)ue_id, (char*)UE_ID, UE_ID_LEN * sizeof(u8)))
	{
		u8 K[KEY_LEN] = { 0x46, 0x5b, 0x5c, 0xe8,
				 		  0xb1, 0x99, 0xb4, 0x9f,
						  0xaa, 0x5f, 0x0a, 0x2e,
						  0xe2, 0x38, 0xa6, 0xbc };

		memcpy(key, K, KEY_LEN * sizeof(u8));
	}
}