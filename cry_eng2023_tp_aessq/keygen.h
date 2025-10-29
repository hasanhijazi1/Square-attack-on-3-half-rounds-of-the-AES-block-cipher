#ifndef KEYGEN_H
#define KEYGEN_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes-128_enc.h"

extern uint8_t ekey1[AES_128_KEY_SIZE];
extern uint8_t ekey2[AES_128_KEY_SIZE];

void genkey(uint8_t* key, int n);
void create_messages(uint8_t x[256][AES_BLOCK_SIZE], int byte);
#endif