#include "Rijndael.h"
#include "utils.h"

#define AES_BLOCK_LEN 16
#define NAS_COUNT_LEN 4
#define PAD_BEARER_LEN 4

class eea_eia
{
public:
	eea_eia();
	~eea_eia();

	u8 *ciph;
	u8 *nas_mac;
	u8 *mac_i;

	void aes_ctr(u8 *key, u8 *input, int input_len, u8 *key_stream);
	void aes_cmac(u8 *key, u8 *input, int input_len, u8 *cmac);

	void EEA2(u8 *key, u8 *count, u8 bearer, u8 direction, u8 *plain, int msg_len); //AES-CTR
	void EIA2(u8 *key, u8 *count, u8 bearer, u8 direction, u8 *message, int len); //AES-CMAC

private:

};
