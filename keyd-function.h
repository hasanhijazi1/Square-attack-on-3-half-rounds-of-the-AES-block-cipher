#ifndef KEYD_FUNCTION_H
#define KEYD_FUNCTION_H
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "aes-128_enc.h"

void keyed_function(uint8_t* block, const uint8_t* key, const uint8_t* key2);
int test_keyed_function();

#endif
