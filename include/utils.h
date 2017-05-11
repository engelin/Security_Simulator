#pragma once
#include "consts.h"

typedef unsigned char u8;

class AUTN {
public:
	u8 sqn[6];
	u8 amf[2];
	u8 mac[8];

};

class AV {
public:
	u8 rand[16];
	u8 res[8];
	AUTN autn;

};