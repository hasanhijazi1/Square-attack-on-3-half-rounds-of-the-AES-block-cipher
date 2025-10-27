#include "aes-128_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * Program to test AES-128 encryption and decryption round key generation
*/
#define random_oracle 0 // Set by challenger

// uint8_t ekey1[AES_128_KEY_SIZE] = { // Encryption key set by challenger
//     43, 113, 41, 39,
//     80, 74, 21, 16,
//     11, 247, 50, 13,
//     156, 72, 77, 9
// };

uint8_t ekey1[AES_128_KEY_SIZE] = { // Encryption key set by challenger
    1, 2, 3, 4,
    5, 6, 7, 8,
    9, 10, 11, 12,
    13, 14, 15, 16
};


uint8_t ekey2[AES_128_KEY_SIZE] = { // Encryption key set by challenger on F PRP game
    1, 101, 199, 250,
    5, 63, 123, 188,
    11, 22, 164, 234,
    50, 100, 150, 200
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

void distinguisher_f(){

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

    printf("Message before keyed function:\n");
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

// Perform an attack on 3 1/2 round AES-128
void create_messages(uint8_t x[256][AES_BLOCK_SIZE], int byte){
    for (int i = 0; i < 256; i++) {
        x[i][byte] = i;

        for (int j = 1; j < AES_128_KEY_SIZE; j++){
            if (j != byte) x[i][j] = 0;
        }
    }
}

void three_half_oracle(uint8_t* block){
    aes128_enc(block, ekey1, 4, 0);
}

void fill_candidates(int candidates[256][AES_128_KEY_SIZE], uint8_t ciphers[256][AES_BLOCK_SIZE]){
    for (int b = 0; b < AES_BLOCK_SIZE; b++) {
        int r = b % 4;
        int c = b / 4;
        int found_candidates = 0;

        for (int guess = 0; guess < 256; guess++){
            uint8_t xor = 0;

            // Compute the origin of the byte before the ShiftRow
            uint8_t col_idx = (c + 4 - r) % 4; // As proposed on NIST, (c-r) mod 4. To avoid negative value in (c-r), we add 4. 
            uint8_t idx = (col_idx * 4) + r; // Compute the index in the array

            // Partially decrypt all ciphertexts
            for (int i = 0; i < 256; i++){
                // Inverse AddRoundKey
                uint8_t tmp = ciphers[i][idx]^guess;
                
                // Inverse ShiftRow and Inverse SubBytes
                tmp = Sinv[tmp];
                xor ^= tmp;
            }

            if (xor == 0){
                candidates[found_candidates][idx] = guess;
                found_candidates++;
            }
        }
    }
}

void attack(){

    // First we query the 3 1/2 oracle with 256 diffrent plaintexts, as in the distinguisher_e function, we do it twice to help us filter out false-positives
    // We partially decrypt the oracle answer by 1/2 rounds.
    //      If the above guess on the byte of the key is correct, we should obtain 256 ciphertexts that XOR to zero (see the distinguisher).
    //      If the guess is incorrect, we should obtain a random value.
    // Then we intersect the candidates obtained from both lambda-sets to find the last round key.
    // We then reverse the extension to find the original key.

    // Start by creating the plaintexts and querying the oracle    
    uint8_t ciphers1[256][AES_BLOCK_SIZE];
    uint8_t ciphers2[256][AES_BLOCK_SIZE];
    
    int guessed_key1[256][AES_128_KEY_SIZE]; // Set of candidates for 1 byte lambda-set -- byte 0
    int guessed_key2[256][AES_128_KEY_SIZE]; // Set of candidates for other lambda-set -- byte 1

    memset(guessed_key1, -1, sizeof(guessed_key1));
    memset(guessed_key2, -1, sizeof(guessed_key2));

    // Creation of plain texts
    create_messages(ciphers1, 0);
    create_messages(ciphers2, 1);
    
    // Query the oracle
    for (int i = 0; i < 256; i++){
        three_half_oracle(ciphers1[i]);
        three_half_oracle(ciphers2[i]);
    }

    // Now, we partially decrypt by 1/2 round with a guessed key
    // We try all possible values for the first byte of the last round key
    fill_candidates(guessed_key1, ciphers1);
    fill_candidates(guessed_key2, ciphers2);

    // Intersection of candidates (between both lambda-set)to find the last round key
    uint8_t recovered_round_key[AES_128_KEY_SIZE];
    
    for (int b = 0; b < AES_128_KEY_SIZE; b++) {
        int found = 0;
        
        for (int i = 0; i < 256; i++){
            if (guessed_key1[i][b] == -1) break;

            for (int k = 0; k < 256; k++){
                if (guessed_key2[k][b] == -1) break;

                if (guessed_key1[i][b] == guessed_key2[k][j]){
                    recovered_round_key[j] = guessed_key1[i][j];
                    found = 1;
                    break;
                }

            }
            
            if (found) break;
        }
    }

    printf("\nRecovered 4th round key bytes (intersection):\n");
    for (int j = 0; j < AES_128_KEY_SIZE; j++){
        printf("%3d ", recovered_round_key[j]);
    }
    printf("\n");

    // Reverse the key extension to find the original key
    uint8_t recovered_key[AES_128_KEY_SIZE];
    uint8_t prev_key[AES_128_KEY_SIZE];
    memcpy(recovered_key, recovered_round_key, AES_128_KEY_SIZE);
    memcpy(prev_key, recovered_round_key, AES_128_KEY_SIZE);
    
    for (int i = 4; i > 0; i--) {
        prev_aes128_round_key(recovered_key, prev_key, i-1);
        memcpy(recovered_key, prev_key, AES_128_KEY_SIZE);
    }

    printf("\nRecovered original key bytes:\n");
    for (int j = 0; j < AES_128_KEY_SIZE; j++){
        printf("%3d ", recovered_key[j]);
    }
    printf("\n");

}

int main(){
    printf("\nTesting round key generation:\n");
    test_round_keys();

    printf("\n\n");

    printf("Testing keyed function:\n");
    test_keyed_function();

    printf("\n\n");

    printf("Testing distinguisher:\n");
    test_distinguisher();

    printf("\n\n");

    printf("Performing attack on 3 1/2 round AES-128:\n");
    //TODO: Must create a random key from urandom and pass as parameter
    attack();
    return 0;
}
