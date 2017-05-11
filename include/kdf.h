#include "hmac_sha256.h"
#include "utils.h"

class kdf
{
public:
	kdf();
	~kdf();

	u8 *string;
	int str_len;

	u8 *derived_key;

	int str_cat(u8 fc, u8 *p0, int l0);
	int str_cat(u8 fc, u8 *p0, int l0, u8 *p1, int l1);

	void key_derivation(u8 *key, int key_len, u8 fc, u8 *p0, int l0);
	void key_derivation(u8 *key, int key_len, u8 fc, u8 *p0, int l0, u8 *p1, int l1);

	void kasme_df(u8 *ck, u8 *ik, u8 *sqn);
	void kenb_df(u8 *kasme, u8 *nas_count);
	void ksec_df(u8 *k, u8 alg_id, u8 alg_dist);

private:

};