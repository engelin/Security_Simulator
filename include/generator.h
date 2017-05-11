#pragma once
#include "utils.h"

class generator
{
public:
	generator();
	~generator();

	u8 *sqn;
	u8 *rand;

	void gen_init();
	void sqn_gen();
	void rand_gen();

private:

};