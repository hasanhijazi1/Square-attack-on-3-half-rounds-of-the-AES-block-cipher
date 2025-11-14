#include "keyd-function.h"


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
