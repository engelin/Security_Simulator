#include "Security_Simulator.h"

#include <stdio.h>

int main()
{
	float fo = 150.34;

	NET = new network;
	eNB = new enb;
	UE = new ue;

	UE->init(fo);
	NET->init(UE->output, fo);

	UE->update(NAS, NET->output, NET->output_len);
	NET->update(UE->output, UE->output_len);
	
	UE->update(NAS, NET->output, NET->output_len);
	NET->update(UE->output, UE->output_len);

	eNB->init(NET->kenb);
	UE->update(RRC, eNB->output, eNB->output_len);
	eNB->update(UE->output, UE->output_len);
}