#include "milenage.h"

u8 OP[16] = { 0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6,
0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18 };

void f1(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], u8 mac_a[8])
{
	u8 op_c[16];
	u8 temp[16];
	u8 in1[16];
	u8 out1[16];
	u8 rijndaelInput[16];
	u8 i;

	RijndaelKeySchedule(k);
	ComputeOPc(op_c);

	for (i = 0; i < 16; i++)
		rijndaelInput[i] = rand[i] ^ op_c[i];
	RijndaelEncrypt(rijndaelInput, temp);

	for (i = 0; i < 6; i++)
	{
		in1[i] = sqn[i];
		in1[i + 8] = sqn[i];
	}
	for (i = 0; i < 2; i++)
	{
		in1[i + 6] = amf[i];
		in1[i + 14] = amf[i];
	}

	for (i = 0; i < 16; i++)
		rijndaelInput[(i + 8) % 16] = in1[i] ^ op_c[i];

	for (i = 0; i < 16; i++)
		rijndaelInput[i] ^= temp[i];
	RijndaelEncrypt(rijndaelInput, out1);

	for (i = 0; i < 16; i++)
		out1[i] ^= op_c[i];
	for (i = 0; i < 8; i++)
		mac_a[i] = out1[i];

	return;
}

void f2345(u8 k[16], u8 rand[16], u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6])
{
	u8 op_c[16];
	u8 temp[16];
	u8 out[16];
	u8 rijndaelInput[16];
	u8 i;

	RijndaelKeySchedule(k);
	ComputeOPc(op_c);

	for (i = 0; i < 16; i++)
		rijndaelInput[i] = rand[i] ^ op_c[i];
	RijndaelEncrypt(rijndaelInput, temp);

	for (i = 0; i < 16; i++)
		rijndaelInput[i] = temp[i] ^ op_c[i];
	rijndaelInput[15] ^= 1;
	RijndaelEncrypt(rijndaelInput, out);

	for (i = 0; i < 16; i++)
		out[i] ^= op_c[i];
	for (i = 0; i < 8; i++)
		res[i] = out[i + 8];
	for (i = 0; i < 6; i++)
		ak[i] = out[i];

	for (i = 0; i < 16; i++)
		rijndaelInput[(i + 12) % 16] = temp[i] ^ op_c[i];
	rijndaelInput[15] ^= 2;
	RijndaelEncrypt(rijndaelInput, out);

	for (i = 0; i < 16; i++)
		out[i] ^= op_c[i];
	for (i = 0; i < 16; i++)
		ck[i] = out[i];

	for (i = 0; i < 16; i++)
		rijndaelInput[(i + 8) % 16] = temp[i] ^ op_c[i];
	rijndaelInput[15] ^= 4;
	RijndaelEncrypt(rijndaelInput, out);

	for (i = 0; i < 16; i++)
		out[i] ^= op_c[i];
	for (i = 0; i < 16; i++)
		ik[i] = out[i];

	return;
}

void f1star(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], u8 mac_s[8])
{
	u8 op_c[16];
	u8 temp[16];
	u8 in1[16];
	u8 out1[16];
	u8 rijndaelInput[16];
	u8 i;

	RijndaelKeySchedule(k);
	ComputeOPc(op_c);

	for (i = 0; i < 16; i++)
		rijndaelInput[i] = rand[i] ^ op_c[i];
	RijndaelEncrypt(rijndaelInput, temp);

	for (i = 0; i < 6; i++)
	{
		in1[i] = sqn[i];
		in1[i + 8] = sqn[i];
	}
	for (i = 0; i < 2; i++)
	{
		in1[i + 6] = amf[i];
		in1[i + 14] = amf[i];
	}

	for (i = 0; i < 16; i++)
		rijndaelInput[(i + 8) % 16] = in1[i] ^ op_c[i];

	for (i = 0; i < 16; i++)
		rijndaelInput[i] ^= temp[i];
	RijndaelEncrypt(rijndaelInput, out1);

	for (i = 0; i < 16; i++)
		out1[i] ^= op_c[i];
	for (i = 0; i < 8; i++)
		mac_s[i] = out1[i + 8];

	return;
}

void f5star(u8 k[16], u8 rand[16], u8 ak[6])
{
	u8 op_c[16];
	u8 temp[16];
	u8 out[16];
	u8 rijndaelInput[16];
	u8 i;

	RijndaelKeySchedule(k);
	ComputeOPc(op_c);

	for (i = 0; i < 16; i++)
		rijndaelInput[i] = rand[i] ^ op_c[i];
	RijndaelEncrypt(rijndaelInput, temp);

	for (i = 0; i < 16; i++)
		rijndaelInput[(i + 4) % 16] = temp[i] ^ op_c[i];
	rijndaelInput[15] ^= 8;
	RijndaelEncrypt(rijndaelInput, out);

	for (i = 0; i < 16; i++)
		out[i] ^= op_c[i];
	for (i = 0; i < 6; i++)
		ak[i] = out[i];

	return;
}

void ComputeOPc(u8 op_c[16])
{
	u8 i;

	RijndaelEncrypt(OP, op_c);

	for (i = 0; i < 16; i++)
		op_c[i] ^= OP[i];

	return;
}