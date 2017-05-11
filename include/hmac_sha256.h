#include "sha.h"

typedef unsigned char u8;

#define BLOCK_LEN 64
#define DIGEST_LEN 32

class hmac
{
public:
	hmac();
	~hmac();

	u8 *si;
	u8 *so;
	u8 *digest;

	void hmac_init(u8 *key, int key_len);
	void hmac_run(u8 *key, int key_len, u8 *message, int msg_len);

private:

};