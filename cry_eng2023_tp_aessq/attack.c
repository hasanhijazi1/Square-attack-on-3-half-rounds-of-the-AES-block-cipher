#include "attack.h"

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

                if (guessed_key1[i][b] == guessed_key2[k][b]){
                    recovered_round_key[b] = guessed_key1[i][b];
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
