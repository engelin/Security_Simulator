#pragma once
#include "utils.h"
#include "sha.h"

class addRandGen
{
public:
	addRandGen();
	~addRandGen();

	u8 *add_rand;

	void additional_rand_gen(float data);
	u8 *float_to_hex(float in);

private:

};