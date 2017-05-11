#pragma once
typedef unsigned char u8;

void RijndaelKeySchedule(u8 key[16]);
void RijndaelEncrypt(u8 input[16], u8 output[16]);
void RijndaelDecrypt(u8 input[16], u8 output[16]);