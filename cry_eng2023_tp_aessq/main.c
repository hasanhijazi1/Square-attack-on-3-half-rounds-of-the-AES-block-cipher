#include "aes-128_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * Program to test AES-128 encryption and decryption round key generation
*/
#define random_oracle 0 // Set by challenger

uint8_t ekey[AES_128_KEY_SIZE] = { // Encryption key set by challenger
    43, 126, 21, 22,
    40, 174, 210, 166,
    171, 247, 151, 103,
    152, 72, 60, 79
};


void keyed_function(uint8_t* block, const uint8_t* key, const uint8_t* key2)
{
    uint8_t block_temp[AES_BLOCK_SIZE] ;
    memcpy(block_temp, block, AES_BLOCK_SIZE);
    
    // Exec AES with 3 full rounds of-128-bit keys
    aes128_enc(block, key, 3, 1);
    aes128_enc(block_temp, key2, 3, 1);

    // Last step: XOR the two results
    for (int i = 0; i < AES_BLOCK_SIZE; i++){
        block[i] ^= block_temp[i];
    }
}

void oracle(uint8_t* block) {
    if (random_oracle) for (int i = 0; i < AES_BLOCK_SIZE; i++) block[i] = rand() % 256; // Random oracle
    else aes128_enc(block, ekey, 3, 1); // 3-full-round AES encryption
}

void challenger_e(uint8_t* block) {
    if (random_oracle) {
        printf("Challenger using random oracle\n");
        oracle(block);
    } else {
        printf("Challenger using E(•)\n");
        oracle(block);
    }
}

void distinguisher_e(){

    uint8_t plaintexts[256][AES_BLOCK_SIZE];
    uint8_t ciphers[256][AES_BLOCK_SIZE];

    // Creation of plain texts
    for (int i = 0; i < 256; i++) {
        plaintexts[i][0] = i;
        ciphers[i][0] = i;

        for (int j = 1; j < AES_BLOCK_SIZE; j++){
            plaintexts[i][j] = 0;
            ciphers[i][j] = 0;
        }
    }

    // Chooses a messages to be sent to the challenger from the set of plaintexts
    int chosen_message_index = rand() % 256;
    uint8_t* m1 = ciphers[chosen_message_index];

    // Sends the messages to the challenger and receives the ciphertexts
    challenger_e(m1);

    // Encrypt all plaintexts with 3-full-round
    for (int i = 0; i < 256; i++){
        if (i == chosen_message_index) continue;
        oracle(ciphers[i]);
    }

    // XOR all ciphertexts
    uint8_t xor_result[AES_BLOCK_SIZE] = {0};
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            xor_result[j] ^= ciphers[i][j];
        }
    }

    // Check if the result is all zero
    int is_all_zero = 1;
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        if (xor_result[i] != 0) {
            is_all_zero = 0;
            break;
        }

    // Simply output the result
    if (is_all_zero) {
        printf("Distinguisher: The oracle is E(•).\n");
    } else {
        printf("Distinguisher: The oracle is a random oracle.\n");
    }
}

int test_distinguisher() {
    distinguisher_e();
    return 0;
}

int test_keyed_function() {
    // Message
    uint8_t block[AES_BLOCK_SIZE] = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
    };

    // Random key 1
    uint8_t key[AES_128_KEY_SIZE] = {
        43, 126, 21, 22,
        40, 174, 210, 166,
        171, 247, 151, 103,
        152, 72, 60, 79
    };

    // Random key 2
    uint8_t key2[AES_128_KEY_SIZE] = {
        60, 79, 37, 54,
        72, 191, 226, 182,
        188, 7, 167, 119,
        168, 131, 44, 123
    };


    printf("Message after keyed function:\n");
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        printf("%d ", block[i]);
    printf("\n");

    keyed_function(block, key, key2);

    printf("Encrypted block:\n");
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        printf("%d ", block[i]);
    printf("\n");

    return 0;
}

int test_round_keys()
{
    uint8_t key[16] = {
        43, 126, 21, 22,
        40, 174, 210, 166,
        171, 247, 151, 103,
        152, 72, 60, 79
    };

    uint8_t round_keys[11][16];
    uint8_t prev_keys[11][16];
    int i;

    // Generate round keys
    for (i = 0; i < 16; i++) {
        round_keys[0][i] = key[i];
    }

    for (i = 0; i < 10; i++) {
        next_aes128_round_key(round_keys[i], round_keys[i + 1], i);
    }

     // Print round keys
     for (i = 0; i <= 10; i++) {
        printf("Round Key %d: ", i);
        for (int j = 0; j < 16; j++) {
            printf("%d ", round_keys[i][j]);
        }
        printf("\n");
    }

    printf("\n");

    //  Generate previous round keys from the last round key
    for (i = 10; i > 0; i--) {
         prev_aes128_round_key(round_keys[i], prev_keys[i - 1], i - 1);
    }

    // Print previous round keys
    for (i = 0; i < 10; i++) {
        printf("Previous Round Key %d: ", i);
        for (int j = 0; j < 16; j++) {
            printf("%d ", prev_keys[i][j]);
        }
        printf("\n");
    }

    printf("\n");

    // Compare generated previous keys with original round keys
    for (i = 0; i < 10; i++) {
        int match = 1;
        for (int j = 0; j < 16; j++) {
            if (prev_keys[i][j] != round_keys[i][j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            printf("Previous Round Key %d matches original Round Key %d\n", i, i);
        } else {
            printf("Previous Round Key %d does NOT match original Round Key %d\n", i, i);
        }
    }


    return 0;
}

int main()
{
    printf("\nTesting round key generation:\n");
    test_round_keys();

    printf("\n\n");

    printf("Testing keyed function:\n");
    test_keyed_function();

    printf("\n\n");

    printf("Testing distinguisher:\n");
    test_distinguisher();

    return 0;
}
