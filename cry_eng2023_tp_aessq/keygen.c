#include "keygen.h"

uint8_t ekey1[AES_128_KEY_SIZE] = { // Encryption key set by challenger
    43, 113, 41, 39,
    80, 74, 21, 16,
    11, 247, 50, 13,
    156, 72, 77, 9
};

uint8_t ekey2[AES_128_KEY_SIZE] = { // Encryption key set by challenger on F PRP game
    1, 101, 199, 250,
    5, 63, 123, 188,
    11, 22, 164, 234,
    50, 100, 150, 200
};


// Load n bytes from /dev/urandom
void genkey(uint8_t* key, int n) {
    FILE* urandom = fopen("/dev/urandom","rb");

    if (urandom == NULL) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }

    size_t bytes = fread(key, sizeof(uint8_t), n, urandom);
    if (bytes != (size_t) n) {
        perror("Failed to load enough random bytes.");
        exit(EXIT_FAILURE);
    }
    
    fclose(urandom);
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
