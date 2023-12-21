#ifndef _TESTS_
#define _TESTS_

#include <vector>
#include <random>
#include <map>
#include <string>
#include <iostream>
#include <math.h>
#include "AES.h"

using namespace std;

typedef unsigned char BYTE;

class Tests {
private:

	vector<BYTE> initVector = { 0x00, 0x01, 0x02, 0x03,
							0x04, 0x05, 0x06, 0x07,
							0x08, 0x09, 0x0A, 0x0B,
							0x0C, 0x0D, 0x0E, 0x0F };

	vector<BYTE> plaintext;
	vector<BYTE> cipertext;
	vector<BYTE> key;
	size_t keyLength;
	size_t keySize;

	AES model;

	map<string, vector<vector<BYTE>>> ciphertexts;

	map<string, vector<float>> freqResults;
	map<string, vector<float>> seriesResults;
	map<string, vector<vector<float>>> autocorResults;
	void keyGeneration();
	void symbolKeyGeneration(BYTE symbol);
	void seriesKeyGeneration();
	void clearKey();

	void printVector(vector<BYTE>& vector);

	vector<float> frequencyTest(vector<vector<BYTE>>& ciphersVector);
	vector<float> seriesTest(vector<vector<BYTE>>& ciphersVector);
	vector<vector<float>> autocorrelationTest(vector<vector<BYTE>>& ciphersVector);

	int onesCounter(BYTE b);
	int zerosCounter(BYTE b);
	int ciphertextBitSize(vector<BYTE>& vector);

	vector<BYTE> shiftCiphertext(vector<BYTE>& ciphertext, int shift);
	vector<BYTE> xorVectors(const vector<BYTE>& first, const vector<BYTE>& second);

	float sumOfSeries(map<int, int>& series, int sezeOfText);

public:

	Tests(string _plaintext, size_t _keyLength);

	void createECBCipherMap();
	void createOFBCipherMap();

	void doTests();

	void showCiphertextsMap();
	void showFloatMap(map<string, vector<float>>& currMap);
	void showAutocorrelation(map <string, vector<vector<float>>>& currMap);
};

#endif // !_TESTS_