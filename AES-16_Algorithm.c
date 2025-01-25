#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

uint8_t sbox[16] = {
    0x6, 0x4, 0xC, 0x5,
    0x0, 0x7, 0x2, 0xE,
    0x1, 0xF, 0xB, 0x9,
    0xD, 0xA, 0x8, 0x3
};

uint8_t inv_sbox[16] = {
    0x4, 0x8, 0x6, 0xF,
    0x1, 0x3, 0x0, 0x5,
    0xE, 0xB, 0xD, 0xA,
    0x2, 0xC, 0x7, 0x9
};

void checkInverseSubstitution(uint8_t value) {
    uint8_t highNibble = (value & 0xF0) >> 4;
    uint8_t lowNibble = value & 0x0F;
}

void substituteBytes(uint8_t state[2]) {
    for (int i = 0; i < 2; i++) {
        uint8_t highNibble = (state[i] & 0xF0) >> 4;
        uint8_t lowNibble = state[i] & 0x0F;
        state[i] = (sbox[highNibble] << 4) | sbox[lowNibble];
    }
    printf("After Substitute Bytes: %02x %02x\n", state[0], state[1]);
}

void inverseSubstituteBytes(uint8_t state[2]) {
    for (int i = 0; i < 2; i++) {
        uint8_t highNibble = (state[i] & 0xF0) >> 4;
        uint8_t lowNibble = state[i] & 0x0F;
        state[i] = (inv_sbox[highNibble] << 4) | inv_sbox[lowNibble];
    }
    printf("After Inverse Substitute Bytes: %02x %02x\n", state[0], state[1]);
}

void shiftRows(uint8_t state[2]) {
    printf("After Shift Rows: %02x %02x\n", state[0], state[1]);
}

void inverseShiftRows(uint8_t state[2]) {
    printf("After Inverse Shift Rows: %02x %02x\n", state[0], state[1]);
}

void mixColumns(uint8_t state[2]) {
    uint8_t temp0 = state[0];
    uint8_t temp1 = state[1];
    state[0] = temp0 ^ temp1;
    state[1] = temp1 ^ temp0;
    printf("After Mix Columns: %02x %02x\n", state[0], state[1]);
}

void xorMixColumns(uint8_t state1[2], uint8_t state2[2]) {
    uint8_t temp0 = state1[0] ^ state2[0];
    uint8_t temp1 = state1[1] ^ state2[1];
    state1[0] = temp1;
    state1[1] = temp0;
    printf("After Mix Columns: %02x %02x\n", state1[0], state1[1]);
}

void addRoundKey(uint8_t state[2], uint8_t key[2]) {
    printf("Round Key: %02x %02x\n", key[0], key[1]);
    state[0] ^= key[0];
    state[1] ^= key[1];
    printf("After Add Round Key: %02x %02x\n", state[0], state[1]);
}

void encrypt(uint8_t plaintext[2], uint8_t key[2], uint8_t afterShiftRows[2]) {
    printf("Start of Round 1: %02x %02x\n", plaintext[0], plaintext[1]);
    substituteBytes(plaintext);
    shiftRows(plaintext);
    afterShiftRows[0] = plaintext[0];
    afterShiftRows[1] = plaintext[1];
    mixColumns(plaintext);
    addRoundKey(plaintext, key);
    printf("Start of Round 2: %02x %02x\n", plaintext[0], plaintext[1]);
    substituteBytes(plaintext);
    shiftRows(plaintext);
    addRoundKey(plaintext, key);
}

void decrypt(uint8_t ciphertext[2], uint8_t key[2], uint8_t afterShiftRows[2]) {
    uint8_t afterAddRoundKey[2];
    printf("Start of Round 1: %02x %02x\n", ciphertext[0], ciphertext[1]);
    addRoundKey(ciphertext, key);
    inverseShiftRows(ciphertext);
    inverseSubstituteBytes(ciphertext);
    printf("Start of Round 2: %02x %02x\n", ciphertext[0], ciphertext[1]);
    addRoundKey(ciphertext, key);
    afterAddRoundKey[0] = ciphertext[0];
    afterAddRoundKey[1] = ciphertext[1];
    xorMixColumns(afterShiftRows, afterAddRoundKey);
    inverseShiftRows(afterShiftRows);
    ciphertext[0] = afterShiftRows[0];
    ciphertext[1] = afterShiftRows[1];
    inverseSubstituteBytes(ciphertext);
}

int main() {
    char str[3];
    char keyStr[3];
    uint8_t keyBytes[2];
    uint8_t afterShiftRows[2];

    while (1) {
        printf("Enter a 2-character string: ");
        scanf("%2s", str);

        if (strlen(str) == 2) {
            break;
        } else {
            printf("Invalid input. Please enter exactly 2 characters.\n");
        }
    }

    while (1) {
        printf("Enter a 2-digit key: ");
        scanf("%2s", keyStr);

        if (strlen(keyStr) == 2 && isdigit(keyStr[0]) && isdigit(keyStr[1])) {
            break;
        } else {
            printf("Invalid input. Please enter exactly 2 digits.\n");
        }
    }

    uint8_t plaintext[2] = {(uint8_t)str[0], (uint8_t)str[1]};

    keyBytes[0] = keyStr[0] - '0';
    keyBytes[1] = keyStr[1] - '0';

    printf("Initial Plaintext: %02x %02x\n", plaintext[0], plaintext[1]);
    printf("Key: %02x %02x\n", keyBytes[0], keyBytes[1]);

    encrypt(plaintext, keyBytes, afterShiftRows);

    printf("The ciphertext is (in ASCII): %02x %02x\n", plaintext[0], plaintext[1]);
    printf("The ciphertext is (in text): %c%c\n", plaintext[0], plaintext[1]);

    decrypt(plaintext, keyBytes, afterShiftRows);

    printf("The decrypted text is (in ASCII): %02x %02x\n", plaintext[0], plaintext[1]);
    printf("The decrypted text is (in text): %c%c\n", plaintext[0], plaintext[1]);

    checkInverseSubstitution(0x2f);

    return 0;
}
