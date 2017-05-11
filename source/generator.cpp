#include "generator.h"
#include <string.h>
#include <stdio.h>

generator::generator()
{
	sqn = new u8[SQN_LENGTH];
	rand = new u8[RAND_LENGTH];

	memset(sqn, 0x00, sizeof(sqn));
	memset(rand, 0x00, sizeof(rand));
}

generator::~generator()
{
	delete sqn;
	delete rand;
}

void
generator::gen_init()
{
	sqn_gen();
	rand_gen();
}

void
generator::sqn_gen()
{
	u8 SQN[6] = { 0xff, 0x9b, 0xb4, 0xd0,
		0xb6, 0x07 };

	memcpy(&sqn, SQN, sizeof(SQN));
}

void
generator::rand_gen()
{
	u8 RAND[16] = { 0x23, 0x55, 0x3c, 0xbe,
		0x96, 0x37, 0xa8, 0x9d,
		0x21, 0x8a, 0xe6, 0x4d,
		0xae, 0x47, 0xbf, 0x35 };

	memcpy(rand, RAND, RAND_LENGTH * sizeof(u8));
}