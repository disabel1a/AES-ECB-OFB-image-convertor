#include "CipherTests.h"

void Tests::keyGeneration() {
	clearKey();

	for (size_t i = 0; i < keySize; i++)
		key.push_back(rand() % 256);
}

void Tests::symbolKeyGeneration(BYTE symbol) {
	clearKey();

	for (size_t i = 0; i < keySize; i++)
		key.push_back(symbol);
}

void Tests::seriesKeyGeneration() {
	clearKey();

	BYTE element = 0x00;
	size_t counter = 4;
	for (size_t i = 0; i < keySize; i++) {
		if (counter == 4)
			element = 0x00;
		else if (counter == 0)
			element = 0xFF;

		key.push_back(element);

		if (element == 0x00)
			counter--;
		else
			counter++;
	}
}

void Tests::clearKey() {
	if (!key.empty())
		key.clear();
}

//void Tests::createCipherMap() {
//	//Ones
//	symbolKeyGeneration(0xFF);
//	cipertext = model.encryptECB(plaintext, key);
//	vector<vector<BYTE>> onesResult;
//	onesResult.push_back(cipertext);
//	ciphertexts.insert({"Ones", onesResult});
//
//	//Zeros
//	symbolKeyGeneration(0x00);
//	cipertext = model.encryptECB(plaintext, key);
//	vector<vector<BYTE>> zerosResult;
//	zerosResult.push_back(cipertext);
//	ciphertexts.insert({ "Zeros", zerosResult });
//
//	//Zeros-Ones
//	seriesKeyGeneration();
//	cipertext = model.encryptECB(plaintext, key);
//	vector<vector<BYTE>> zerosOnesResult;
//	zerosOnesResult.push_back(cipertext);
//	ciphertexts.insert({ "Zeros_Ones", zerosOnesResult });
//
//	//Generated
//	vector<vector<BYTE>> generatedResults;
//	unsigned int rounds = model.getNumberRounds();
//	for (unsigned int i = 0; i < rounds; i++) {
//		keyGeneration();
//		cipertext = model.encryptECB(plaintext, key);
//		generatedResults.push_back(cipertext);
//	}
//	ciphertexts.insert({ "Generated", generatedResults });
//}

void Tests::createOFBCipherMap() {
	unsigned int rounds = model.getNumberRounds();
	//Ones
	vector<vector<BYTE>> onesResult;
	for (unsigned int i = 0; i < rounds; i++) {
		symbolKeyGeneration(0xFF);
		cipertext = model.encryptOFB(plaintext, initVector, key);
		onesResult.push_back(cipertext);
	}
	ciphertexts.insert({ "Ones", onesResult });

	//Zeros
	vector<vector<BYTE>> zerosResult;
	for (unsigned int i = 0; i < rounds; i++) {
		symbolKeyGeneration(0x00);
		cipertext = model.encryptOFB(plaintext, initVector, key);
		zerosResult.push_back(cipertext);
	}
	ciphertexts.insert({ "Zeros", zerosResult });

	//Zeros-Ones
	vector<vector<BYTE>> zerosOnesResult;
	for (unsigned int i = 0; i < rounds; i++) {
		seriesKeyGeneration();
		cipertext = model.encryptOFB(plaintext, initVector, key);
		zerosOnesResult.push_back(cipertext);
	}
	ciphertexts.insert({ "Zeros_Ones", zerosOnesResult });

	//Generated
	vector<vector<BYTE>> generatedResults;
	for (unsigned int i = 0; i < rounds; i++) {
		keyGeneration();
		cipertext = model.encryptOFB(plaintext, initVector, key);
		generatedResults.push_back(cipertext);
	}
	ciphertexts.insert({ "Generated", generatedResults });
}

void Tests::createECBCipherMap() {
	unsigned int rounds = model.getNumberRounds();
	//Ones
	vector<vector<BYTE>> onesResult;
	for (unsigned int i = 0; i < rounds; i++) {
		symbolKeyGeneration(0xFF);
		cipertext = model.encryptECB(plaintext, key);
		onesResult.push_back(cipertext);
	}
	ciphertexts.insert({ "Ones", onesResult });

	//Zeros
	vector<vector<BYTE>> zerosResult;
	for (unsigned int i = 0; i < rounds; i++) {
		symbolKeyGeneration(0x00);
		cipertext = model.encryptECB(plaintext, key);;
		zerosResult.push_back(cipertext);
	}
	ciphertexts.insert({ "Zeros", zerosResult });

	//Zeros-Ones
	vector<vector<BYTE>> zerosOnesResult;
	for (unsigned int i = 0; i < rounds; i++) {
		seriesKeyGeneration();
		cipertext = model.encryptECB(plaintext, key);
		zerosOnesResult.push_back(cipertext);
	}
	ciphertexts.insert({ "Zeros_Ones", zerosOnesResult });

	//Generated
	vector<vector<BYTE>> generatedResults;
	for (unsigned int i = 0; i < rounds; i++) {
		keyGeneration();
		cipertext = model.encryptECB(plaintext, key);
		generatedResults.push_back(cipertext);
	}
	ciphertexts.insert({ "Generated", generatedResults });
}

void Tests::printVector(vector<BYTE>& vector) {
	for (BYTE b : vector) {
		cout << b;
	}
	cout << '\t';
}

void Tests::showCiphertextsMap() {
	map<string, vector<vector<BYTE>>>::iterator it;
	for (it = ciphertexts.begin(); it != ciphertexts.end(); it++) {
		cout << it->first << ":" << endl;
		for (size_t i = 0; i < it->second.size(); i++) {
			printVector(it->second[i]);
		}
		cout << endl;
	}
}

Tests::Tests(string _plaintext, size_t _keyLength) {
	plaintext = vector<BYTE>(_plaintext.begin(), _plaintext.end());
	keyLength = _keyLength;
	switch (_keyLength)
	{
	case(128):
		model = AES{ AESKeyLength::AES_128 };
		keySize = 16;
		break;
	case(192):
		model = AES{ AESKeyLength::AES_192 };
		keySize = 24;
		break;
	case(256):
		model = AES{ AESKeyLength::AES_256 };
		keySize = 32;
		break;
	default:
		break;
	}
	srand(time(NULL));
}

void Tests::doTests() {
	map<string, vector<vector<BYTE>>>::iterator it;
	string name;
	for (it = ciphertexts.begin(); it != ciphertexts.end(); it++) {
		name = it->first;
		freqResults.insert({ name, frequencyTest(it->second) });
		seriesResults.insert({ name, seriesTest(it->second) });
		autocorResults.insert({ name, autocorrelationTest(it->second) });
	}

	cout << endl << "Frequency test: " << endl;
	showFloatMap(freqResults);
	cout << endl << "Series test: " << endl;
	showFloatMap(seriesResults);
	cout << endl << "Autocorrelation test: " << endl;
	//showFloatMap(autocorResults);
	showAutocorrelation(autocorResults);
}

vector<float> Tests::frequencyTest(vector<vector<BYTE>>& ciphersVector) {
	int ones = 0;
	int zeros = 0;
	float stat = 0;
	vector<float> stats;
	for (size_t i = 0; i < ciphersVector.size(); i++) {
		for (BYTE b : ciphersVector[i]) {
			ones += onesCounter(b);
			zeros += zerosCounter(b);
		}
		//zeros = ciphertextBitSize(ciphersVector[i]) - ones;
		cout << "z:" << zeros << " o:" << ones << endl;
		stat = pow((float)(zeros - ones), 2.0) / ciphertextBitSize(ciphersVector[i]);
		stats.push_back(stat);

		stat = 0;
		zeros = 0;
		ones = 0;
	}
	return stats;
}

int Tests::ciphertextBitSize(vector<BYTE>& vector) {
	return vector.size() * 8;
}

int Tests::onesCounter(BYTE b) {
	int counter = 0;
	for (size_t i = 0; i < 8; i++) {
		if (b & 1)
			counter++;
		b = (b >> 1);
	}
	return counter;
}

int Tests::zerosCounter(BYTE b) {
	int counter = 0;
	for (size_t i = 0; i < 8; i++) {
		if (!(b & 1))
			counter++;
		b = (b >> 1);
	}
	return counter;
}

vector<float> Tests::seriesTest(vector<vector<BYTE>>& ciphersVector) {
	map<int, int> onesSeriesMap;
	map<int, int> zerosSeriesMap;
	int seriaSize = 0;
	bool lastElement = false;
	bool isFirst = true;
	vector<float> results;
	for (size_t i = 0; i < ciphersVector.size(); i++) {
		for (BYTE b : ciphersVector[i]) {
			if (isFirst) {
				if ((b & 0x08) == 0x08)
					lastElement = true;
				isFirst = false;
			}
			for (size_t j = 0; j < 8; j++) {
				if (lastElement) {
					if ((b & 0x08) == 0x08)
						seriaSize++;
					else {
						onesSeriesMap[seriaSize]++;
						seriaSize = 1;
						lastElement = false;
					}
				}
				else {
					if (b & 0x00)
						seriaSize++;
					else {
						zerosSeriesMap[seriaSize]++;
						seriaSize = 1;
						lastElement = true;
					}
				}
				b = (b << 1);
;			}
		}
		isFirst = true;
		lastElement = false;
		seriaSize = 0;

		results.push_back(sumOfSeries(onesSeriesMap, ciphertextBitSize(ciphersVector[i])
			+ sumOfSeries(zerosSeriesMap, ciphertextBitSize(ciphersVector[i]))));

		zerosSeriesMap.clear();
		onesSeriesMap.clear();
	}
	return results;
}

float Tests::sumOfSeries(map<int, int>& series, int sizeofText) {
	map<int, int>::iterator it;
	int currSeria = 0;
	float e = 0;
	float sum = 0;

	//If need to count key -> null series
	/*for (size_t i = 1; i < series.rbegin()->first; i++) {
		if (series.count(i) > 0)
			currSeria = series.at(i);

		e = (sizeofText - i + 3) / pow(2, (i + 2));
		sum += pow((currSeria - e), 2) / e;
		currSeria = 0;
	}*/

	//If don't need to count key -> null series
	for (it = series.begin(); it != series.end(); it++) {
		e = (sizeofText - it->second + 3) / pow(2, (it->second + 2));
		sum += pow((currSeria - e), 2) / e;
		currSeria = 0;
	}

	return sum;
}

vector<vector<float>> Tests::autocorrelationTest(vector<vector<BYTE>>& ciphersVector) {
	vector<BYTE> xoredCiphertext;
	int counter = 0;
	int ciphertextSize = 0;
	vector<vector<float>> results;
	vector<float> shiftedResult;
	for (size_t i = 0; i < ciphersVector.size(); i++) {
		for (size_t shift = 0; shift < (ciphersVector[i].size() / 2); shift++) {
			xoredCiphertext = xorVectors(ciphersVector[i], shiftCiphertext(ciphersVector[i], shift));
			for (BYTE b : xoredCiphertext) {
				counter += onesCounter(b);
			}

			cout << counter << endl;

			//ciphertextSize = ciphertextBitSize(ciphersVector[i]);
			ciphertextSize = 128;
			if(shift == 0)
				shiftedResult.push_back(2 * (counter - (ciphertextSize - 1) / 2) / sqrt(ciphertextSize - 1));
			else
				shiftedResult.push_back(2 * (counter - (ciphertextSize - shift * 8) / 2) / sqrt(ciphertextSize - shift * 8));

			xoredCiphertext.clear();
			counter = 0;
			ciphertextSize = 0;
		}
		results.push_back(shiftedResult);
		shiftedResult.clear();
	}
	return results;
}

vector<BYTE> Tests::shiftCiphertext(vector<BYTE>& ciphertext, int shift) {
	vector<BYTE> shiftedCiphertext;
	/*if (shift % 4 == 0) {
		for (int i = 0; i < (shift / 4); i++)
			shiftedCiphertext.push_back(0x00);

		for (int i = 0; i < ciphertext.size() - (shift / 4); i++)
			shiftedCiphertext.push_back(ciphertext[i]);
	}
	return shiftedCiphertext;*/
	for (size_t i = 0; i < shift; i++) {
		shiftedCiphertext.push_back(0x00);
	}
	for (size_t i = 0; i < ciphertext.size() - shift; i++) {
		shiftedCiphertext.push_back(ciphertext[i]);
	}
	return shiftedCiphertext;
}

vector<BYTE> Tests::xorVectors(const vector<BYTE>& first, const vector<BYTE>& second) {
	vector<BYTE> result;
	for (size_t i = 0; i < first.size(); i++)
		result.push_back(first[i] ^ second[i]);
	return result;
}

void Tests::showFloatMap(map<string, vector<float>>& currMap) {
	map<string, vector<float>>::iterator it;
	for (it = currMap.begin(); it != currMap.end(); it++) {
		cout << it->first << ":" << endl;
		for (size_t i = 0; i < it->second.size(); i++) {
			cout << it->second[i] << '\t';
		}
		cout << endl;
	}
}

void Tests::showAutocorrelation(map <string, vector<vector<float>>>& currMap) {
	map<string, vector<vector<float>>>::iterator it;
	for (it = currMap.begin(); it != currMap.end(); it++) {
		cout << it->first << ":" << endl;
		for (size_t i = 0; i < it->second.size(); i++) {
			cout << "Gen (" << i << "): " << endl;
			for (size_t j = 0; j < it->second[i].size(); j++) {
				cout << it->second[i].at(j) << "\t";
			}
			cout << endl;
		}
		cout << endl;
	}
}