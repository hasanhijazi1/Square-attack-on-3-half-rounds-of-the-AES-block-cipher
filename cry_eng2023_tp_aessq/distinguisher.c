#include "distinguisher.h"

int random_oracle = 0;

void oracle(uint8_t* block) {
    if (random_oracle) for (int i = 0; i < AES_BLOCK_SIZE; i++) block[i] = rand() % 256; // Random oracle
    else aes128_enc(block, ekey1, 3, 1); // 3-full-round AES encryption
}

void oraclef(uint8_t* block) {
    if (random_oracle) for (int i = 0; i < AES_BLOCK_SIZE; i++) block[i] = rand() % 256; // Random oracle
    else keyed_function(block, ekey1, ekey2); // 3-full-round AES encryption
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

void challenger_f(uint8_t* block) {
    if (random_oracle) {
        printf("Challenger using random oracle\n");
        oraclef(block);
    } else {
        printf("Challenger using F(•)\n");
        oraclef(block);
    }
}

void distinguisher_e(){

    // uint8_t plaintexts[256][AES_BLOCK_SIZE];
    uint8_t ciphers[256][AES_BLOCK_SIZE];

    // Creation of plain texts
    for (int i = 0; i < 256; i++) {
        // plaintexts[i][0] = i;
        ciphers[i][0] = i;

        for (int j = 1; j < AES_BLOCK_SIZE; j++){
            // plaintexts[i][j] = 0;
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

void distinguisher_f(){

    // uint8_t plaintexts[256][AES_BLOCK_SIZE];
    uint8_t ciphers[256][AES_BLOCK_SIZE];

    // Creation of plain texts
    for (int i = 0; i < 256; i++) {
        // plaintexts[i][0] = i;
        ciphers[i][0] = i;

        for (int j = 1; j < AES_BLOCK_SIZE; j++){
            // plaintexts[i][j] = 0;
            ciphers[i][j] = 0;
        }
    }

    // Chooses a messages to be sent to the challenger from the set of plaintexts
    int chosen_message_index = rand() % 256;
    uint8_t* m1 = ciphers[chosen_message_index];

    // Sends the messages to the challenger and receives the ciphertexts
    challenger_f(m1);

    // Encrypt all plaintexts with 3-full-round
    for (int i = 0; i < 256; i++){
        if (i == chosen_message_index) continue;
        oraclef(ciphers[i]);
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
        printf("Distinguisher: The oracle is F(•).\n");
    } else {
        printf("Distinguisher: The oracle is a random oracle.\n");
    }
}


int test_distinguisher() {
    distinguisher_e();
    distinguisher_f();
    return 0;
}