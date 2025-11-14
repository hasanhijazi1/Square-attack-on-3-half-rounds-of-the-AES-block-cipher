#ifndef DISTINGUISHER_H
#define DISTINGUISHER_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "keygen.h"
#include "aes-128_enc.h"
#include "keyd-function.h"

extern int random_oracle; // Set by challenger

void distinguisher_e();
void distinguisher_f();
int test_distinguisher();
#endif
