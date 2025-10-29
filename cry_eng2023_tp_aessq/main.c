#include "aes-128_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keygen.h"
#include "distinguisher.h"
#include "attack.h"
#include "keyd-function.h"

/**
 * Program to test AES-128 encryption and decryption round key generation
 */

int main(int argc, char *argv[])
{

    // Set the oracle type based on command line argument
    if (argc > 1) {
        if (strcmp(argv[1], "random") == 0) {
            random_oracle = 1;
            printf("Using random oracle for the tests.\n\n");
        } else {
            random_oracle = 0;
            printf("Using E(•)/F(•) oracle for the tests.\n\n");
        }
    } else {
        random_oracle = 0;
        printf("Using E(•)/F(•) oracle for the tests.\n\n");
    }
make_new_sbox(0xA5);
    // Perform tests
    printf("-> Testing round key generation:\n");
    test_round_keys();

    printf("\n\n");

    printf("-> Testing keyed function:\n");
    test_keyed_function();

    printf("\n\n");

    printf("-> Testing distinguisher:\n");
    test_distinguisher();

    printf("\n\n");

    uint8_t key[AES_128_KEY_SIZE];
    genkey(key, AES_128_KEY_SIZE);
    printf("-> Randomly generated key for the attack:\n");
    for (int i = 0; i < AES_128_KEY_SIZE; i++){
        printf("%3d ", key[i]);
    }
    printf("\n\n");

    printf("-> Performing attack on 3 1/2 round AES-128:\n");
    memcpy(ekey1, key, AES_128_KEY_SIZE); // Set the key for the oracle
    attack();
    return 0;

    
}
