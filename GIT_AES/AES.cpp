#include "AES.h"

AES::AES(const AESKeyLength keyLength) {
    switch (keyLength) {
    case AESKeyLength::AES_128:
        this->Nk = 4;
        this->Nr = 10;
        break;
    case AESKeyLength::AES_192:
        this->Nk = 6;
        this->Nr = 12;
        break;
    case AESKeyLength::AES_256:
        this->Nk = 8;
        this->Nr = 14;
        break;
    }
}

BYTE* AES::encryptECB(const BYTE plaintext[], WORD textLenght, const BYTE key[]) {

    BYTE* ciphertext = new BYTE[textLenght];
    BYTE* roundKeys = new BYTE[4 * Nb * (Nr + 1)];

    keyExpansion(key, roundKeys);
    for (WORD i = 0; i < textLenght; i += blockSize) {
        encryptBlock(plaintext + i, ciphertext + i, roundKeys);
    }

    delete[] roundKeys;

    return ciphertext;
}

BYTE* AES::decryptECB(const BYTE ciphertext[], WORD textLenght, const BYTE key[]) {
    BYTE* plaintext = new BYTE[textLenght];
    BYTE* roundKeys = new BYTE[4 * Nb * (Nr + 1)];

    keyExpansion(key, roundKeys);
    for (WORD i = 0; i < textLenght; i += blockSize) {
        decryptBlock(ciphertext + i, plaintext + i, roundKeys);
    }

    delete[] roundKeys;

    return plaintext;
}

vector<BYTE> AES::encryptECB(vector<BYTE> input, vector<BYTE> key)
{
    while (input.size() % blockSize != 0) {
        input.push_back('\0');
    }

    BYTE* output = encryptECB(VectorToArray(input), (WORD) input.size(), VectorToArray(key));

    vector<BYTE> out = ArrayToVector(output, input.size());

    delete[] output;

    return out;
}

vector<BYTE> AES::decryptECB(vector<BYTE> input, vector<BYTE> key)
{
    BYTE* output = decryptECB(VectorToArray(input), (WORD)input.size(), VectorToArray(key));

    vector<BYTE> out = ArrayToVector(output, input.size());

    delete[] output;

    while (out.back() == '\0')
    {
        out.pop_back();
    }

    return out;
}

vector<BYTE> AES::encryptECBImage(vector<BYTE> input, vector<BYTE> key) {
    
    WORD addedBytes = 0;
    while (input.size() % blockSize != 0) {
        input.push_back('\0');
        addedBytes++;
    }

    BYTE* output = encryptECB(VectorToArray(input), (WORD)input.size(), VectorToArray(key));

    vector<BYTE> out = ArrayToVector(output, input.size());

    delete[] output;

    while (addedBytes > 0) {
        out.pop_back();
        addedBytes--;
    }

    return out;
}

vector<BYTE> AES::decryptECBImage(vector<BYTE> input, vector<BYTE> key) {

    WORD addedBytes = 0;
    while (input.size() % blockSize != 0) {
        input.push_back('\0');
        addedBytes++;
    }

    BYTE* output = decryptECB(VectorToArray(input), (WORD)input.size(), VectorToArray(key));

    vector<BYTE> out = ArrayToVector(output, input.size());

    delete[] output;

    while (addedBytes > 0) {
        out.pop_back();
        addedBytes--;
    }

    return out;
}

BYTE* AES::encryptOFB(const BYTE plaintext[], BYTE* initVector, WORD textLenght, const BYTE key[])
{
    BYTE* out = new BYTE[textLenght];
    BYTE inBlock[blockSize];
    BYTE outBlock[blockSize];
    BYTE* roundKeys = new BYTE[4 * Nb * (Nr + 1)];

    keyExpansion(key, roundKeys);
    memcpy(inBlock, initVector, blockSize);

    for (size_t i = 0; i < textLenght; i += blockSize) {
        encryptBlock(inBlock, outBlock, roundKeys);
        memcpy(inBlock, plaintext + i, blockSize);

        xorBlocks(inBlock, outBlock, out + i, blockSize);
        memcpy(inBlock, outBlock, blockSize);
    }

    delete[] roundKeys;

    return out;
}

BYTE* AES::decryptOFB(const BYTE ciphertext[], BYTE* initVector, WORD textLenght, const BYTE key[])
{
    BYTE* out = new BYTE[textLenght];
    BYTE inBlock[blockSize];
    BYTE outBlock[blockSize];
    BYTE* roundKeys = new BYTE[4 * Nb * (Nr + 1)];

    keyExpansion(key, roundKeys);
    memcpy(inBlock, initVector, blockSize);

    for (size_t i = 0; i < textLenght; i += blockSize) {
        encryptBlock(inBlock, outBlock, roundKeys);
        memcpy(inBlock, ciphertext + i, blockSize);

        xorBlocks(inBlock, outBlock, out + i, blockSize);
        memcpy(inBlock, outBlock, blockSize);
    }

    delete[] roundKeys;

    return out;
}

vector<BYTE> AES::encryptOFB(vector<BYTE> input, vector<BYTE> initVector, vector<BYTE> key)
{
    while (input.size() % blockSize != 0) {
        input.push_back('\0');
    }

    BYTE* output = encryptOFB(VectorToArray(input), VectorToArray(initVector), (WORD)input.size(), VectorToArray(key));

    vector<BYTE> out = ArrayToVector(output, input.size());

    delete[] output;

    return out;
}

vector<BYTE> AES::decryptOFB(vector<BYTE> input, vector<BYTE> initVector, vector<BYTE> key)
{
    BYTE* output = decryptOFB(VectorToArray(input), VectorToArray(initVector), (WORD)input.size(), VectorToArray(key));

    vector<BYTE> out = ArrayToVector(output, input.size());

    delete[] output;

    while (out.back() == '\0')
    {
        out.pop_back();
    }

    return out;
}

vector<BYTE> AES::encryptOFBImage(vector<BYTE> input, vector<BYTE> initVector, vector<BYTE> key)
{
    WORD addedBytes = 0;
    while (input.size() % blockSize != 0) {
        input.push_back('\0');
        addedBytes++;
    }

    BYTE* output = encryptOFB(VectorToArray(input), VectorToArray(initVector), (WORD)input.size(), VectorToArray(key));

    vector<BYTE> out = ArrayToVector(output, input.size());

    delete[] output;

    while (addedBytes > 0) {
        out.pop_back();
        addedBytes--;
    }

    return out;
}

vector<BYTE> AES::decryptOFBImage(vector<BYTE> input, vector<BYTE> initVector, vector<BYTE> key)
{
    WORD addedBytes = 0;
    while (input.size() % blockSize != 0) {
        input.push_back('\0');
        addedBytes++;
    }

    BYTE* output = decryptOFB(VectorToArray(input), VectorToArray(initVector), (WORD)input.size(), VectorToArray(key));

    vector<BYTE> out = ArrayToVector(output, input.size());

    delete[] output;

    while (addedBytes > 0) {
        out.pop_back();
        addedBytes--;
    }

    return out;
}

int AES::checkLength(WORD len) {
    if (len % blockSize != 0) {
        return 404;
    }
}

void AES::encryptBlock(const BYTE plaintext[], BYTE ciphertext[], BYTE* roundKeys) {
    BYTE state[4][Nb];
    WORD i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = plaintext[i + 4 * j];
        }
    }

    addRoundKey(state, roundKeys);

    for (round = 1; round <= Nr - 1; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + round * 4 * Nb);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            ciphertext[i + 4 * j] = state[i][j];
        }
    }
}

void AES::decryptBlock(const BYTE ciphertext[], BYTE plaintext[], BYTE* roundKeys) {
    BYTE state[4][Nb];
    WORD i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = ciphertext[i + 4 * j];
        }
    }

    addRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--) {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(state, roundKeys + round * 4 * Nb);
        invMixColumns(state);
    }

    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            plaintext[i + 4 * j] = state[i][j];
        }
    }
}

void AES::xorBlocks(BYTE* first, BYTE* second, BYTE* out, WORD len) {
    for (WORD i = 0; i < len; i++) {
        out[i] = first[i] ^ second[i];
    }
}

void AES::subBytes(BYTE state[4][Nb]) {
    WORD i, j;
    BYTE element;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            element = state[i][j];
            state[i][j] = sbox[element / 16][element % 16];
        }
    }
}

void AES::shiftRows(BYTE state[4][Nb]) {
    BYTE tmp[4][Nb];
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < Nb; j++) {
            tmp[i][j] = state[i][(j + i) % Nb];
        }
    for (i = 0; i < 4; i++) {
        memcpy(state[i], tmp[i], 4);
    }
}

void AES::mixColumns(BYTE state[4][Nb]) {
    BYTE temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                if (mixPolynom[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= multTable[mixPolynom[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::addRoundKey(BYTE state[4][Nb], BYTE* key) {
    WORD i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}

void AES::subWord(BYTE* word) {
    int i;
    for (i = 0; i < 4; i++) {
        word[i] = sbox[word[i] / 16][word[i] % 16];
    }
}

void AES::rotWord(BYTE* word) {
    unsigned char c = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = c;
}

void AES::xorWords(BYTE* word, BYTE* key, BYTE* result) {
    for (int i = 0; i < 4; i++) {
        result[i] = word[i] ^ key[i];
    }
}

void AES::getRcon(BYTE* rcon, WORD index) {
    for (int i = 0; i < 4; i++) {
        rcon[i] = rconTable[index][i];
    }
}

void AES::keyExpansion(const BYTE key[], BYTE w[]) {
    BYTE temp[4];
    BYTE rcon[4];

    WORD i = 0;
    while (i < 4 * Nk) {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0) {
            rotWord(temp);
            subWord(temp);
            getRcon(rcon, i / (Nk * 4));
            xorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4) {
            subWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }
}

void AES::invSubBytes(BYTE state[4][Nb]) {
    WORD i, j;
    BYTE t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = invSbox[t / 16][t % 16];
        }
    }
}

void AES::invMixColumns(BYTE state[4][Nb]) {
    BYTE temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                temp_state[i][j] ^= multTable[invMixPolynom[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::invShiftRows(BYTE state[4][Nb]) {
    BYTE tmp[4][Nb];
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < Nb; j++) {
            tmp[i][j] = state[i][(j - i) % Nb];
        }
    for (i = 0; i < 4; i++) {
        memcpy(state[i], tmp[i], 4);
    }
}

std::vector<unsigned char> AES::ArrayToVector(unsigned char* a, unsigned int len)
{
    std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
    return v;
}

unsigned char* AES::VectorToArray(std::vector<unsigned char>& a)
{
    return a.data();
}
