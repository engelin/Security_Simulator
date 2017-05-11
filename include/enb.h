#include "utils.h"

#include "kdf.h"
#include "eea_eia.h"
#include "rrc_pdu.h"

class enb
{
public:
	enb();
	~enb();

	u8 *output;
	int output_len;

	u8 *kenb;
	u8 *krrc_int;
	u8 *krrc_enc;
	u8 *kup_enc;

	rrc_pdu *rrc;

	u8 *rrc_message;
	int rrc_message_len;
	u8 *mac_i;

	void init(u8 *k);
	void update(u8 *input, int input_len);

	void sec_mode_command(u8 encID, u8 incID);

private:

};