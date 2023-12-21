#include "AES.h"
#include "ImageConvertor.h"
#include "CipherTests.h"
#include <stdint.h>
#include <string>
#include <iostream>
#include <vector>
#include <random>

using namespace std;

typedef unsigned char BYTE;

vector<BYTE> initVector = { 0x00, 0x01, 0x02, 0x03,
							0x04, 0x05, 0x06, 0x07,
							0x08, 0x09, 0x0A, 0x0B,
							0x0C, 0x0D, 0x0E, 0x0F };

// Функция для вычисления среднего значения
double calculateMean(const std::vector<unsigned char>& data)
{
	double sum = 0;
	for (const uint32_t& value : data)
	{
		sum += value;
	}
	return sum / data.size();
}

// Функция для вычисления среднеквадратического отклонения
double calculateStandardDeviation(const std::vector<unsigned char>& data, double mean)
{
	double variance = 0;
	for (const uint32_t& value : data)
	{
		variance += pow(value - mean, 2);
	}
	variance /= data.size();
	return sqrt(variance);
}

double countCorell(const std::vector<unsigned char>& plain, const std::vector<unsigned char>& cipher)
{

	double meanPlain = calculateMean(plain);
	double meanCipher = calculateMean(cipher);

	double stdDevPlain = calculateStandardDeviation(plain, meanPlain);
	double stdDevCipher = calculateStandardDeviation(cipher, meanCipher);

	double correlation = 0;
	for (size_t i = 0; i < plain.size(); ++i)
	{
		correlation += (plain[i] - meanPlain) * (cipher[i] - meanCipher);
	}
	correlation /= (stdDevPlain * stdDevCipher * plain.size());

	return correlation;
}

void correlationTest() {
	string inputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/bird.bmp";
	string cipheredFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/result.bmp";

	IMG convertor;

	vector<BYTE> inputBytes = convertor.toBytes(inputFilePath);
	vector<BYTE> cipheredBytes = convertor.toBytes(cipheredFilePath);

	cout << "corr:" << countCorell(inputBytes, cipheredBytes) << endl;
}

vector<BYTE> generateKey(size_t len) {
	srand(time(NULL));

	size_t bytes = len / 8;

	vector<BYTE> key;
	for (size_t i = 0; i < bytes; i++)
		key.push_back(rand() % 256);

	cout << "\nGenerated key: " << endl;

	for (BYTE b : key) {
		cout << b;
	}
	cout << endl;

	return key;
}

vector<BYTE> generateKeyConstruct(string keyLength) {
	vector<BYTE> keyV;
	while (true) {
		cout << "Generate or enter key (g) or (e): ";
		char keyMarker;
		cin >> keyMarker;

		switch (keyMarker)
		{
		case ('g'): {
			keyV = generateKey(stoi(keyLength));
			break;
		}
		case ('e'): {
			string key;
			cout << "Enter key with lenght(" << keyLength << "): " << endl;
			cin >> key;
			copy(key.begin(), key.end(), back_inserter(keyV));
			break;
		}
		default:
			continue;
		}
		break;
	}
	return keyV;
}

void printVector(vector<BYTE>& vector, string title) {
	cout << "\n" << title << ": " << endl;
	for (BYTE b : vector) {
		cout << b;
	}
	cout << '\n';
}

vector<BYTE> getPlaintext() {
	string plaintext;
	cout << "Enter plaintext: " << endl;
	cin >> plaintext;

	vector<BYTE> plaintextV(plaintext.begin(), plaintext.end());
	return plaintextV;
}

void testConsoleOutECB() {

	vector<BYTE> plaintextV = getPlaintext();

	string keyLength;
	cout << "Enter key lenght 128/192/256: " << endl;
	cin >> keyLength;

	AESKeyLength ks;

	if (keyLength == "128")
		ks = AESKeyLength::AES_128;
	else if (keyLength == "192")
		ks = AESKeyLength::AES_192;
	else if (keyLength == "256")
		ks = AESKeyLength::AES_256;

	vector<BYTE> keyV = generateKeyConstruct(keyLength);

	AES model{ ks };

	vector<BYTE> ciphertextV = model.encryptECB(plaintextV, keyV);
	printVector(ciphertextV, "Ciphertext");

	vector<BYTE> decryptedCiphertext = model.decryptECB(ciphertextV, keyV);
	printVector(decryptedCiphertext, "Decrypted text");
}

void imageTestECB() {
	string inputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/bird.bmp";
	string middleFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/result.bmp";
	string outputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/last.bmp";

	string key = "mamapapamamapapa";
	vector<BYTE> keyV(key.begin(), key.end());

	IMG convertor;

	vector<BYTE> imageBytes = convertor.toBytes(inputFilePath);

	AES model{ AESKeyLength::AES_128 };

	vector<BYTE> encryptedImage = model.encryptECBImage(imageBytes, keyV);

	convertor.toImage(middleFilePath, encryptedImage);

	vector<BYTE> decryptedImage = model.decryptECBImage(encryptedImage, keyV);

	convertor.toImage(outputFilePath, decryptedImage);
}

void testConsoleOutOFB() {

	vector<BYTE> plaintextV = getPlaintext();

	string keyLength;
	cout << "Enter key lenght 128/192/256: " << endl;
	cin >> keyLength;

	AESKeyLength ks;

	if (keyLength == "128")
		ks = AESKeyLength::AES_128;
	else if (keyLength == "192")
		ks = AESKeyLength::AES_192;
	else if (keyLength == "256")
		ks = AESKeyLength::AES_256;

	vector<BYTE> keyV = generateKeyConstruct(keyLength);

	AES model{ ks };

	vector<BYTE> ciphertextV = model.encryptOFB(plaintextV, initVector, keyV);
	printVector(ciphertextV, "Ciphertext");

	vector<BYTE> decryptedCiphertext = model.decryptOFB(ciphertextV, initVector, keyV);
	printVector(decryptedCiphertext, "Decrypted text");
}

void imageTestOFB() {
	string inputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/OFB/bird.bmp";
	string middleFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/OFB/result.bmp";
	string outputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/OFB/last.bmp";

	string key = "mamapapamamapapa";
	vector<BYTE> keyV(key.begin(), key.end());

	IMG convertor;

	vector<BYTE> imageBytes = convertor.toBytes(inputFilePath);

	AES model{ AESKeyLength::AES_128 };

	vector<BYTE> encryptedImage = model.encryptOFBImage(imageBytes, initVector,keyV);

	convertor.toImage(middleFilePath, encryptedImage);

	vector<BYTE> decryptedImage = model.decryptOFBImage(encryptedImage, initVector, keyV);

	convertor.toImage(outputFilePath, decryptedImage);
}

void pixelErrorTest() {
	string inputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/Pixel/result.bmp";
	string outputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/Pixel/last.bmp";

	string key = "mamapapamamapapa";
	vector<BYTE> keyV(key.begin(), key.end());

	IMG convertor;

	vector<BYTE> imageBytes = convertor.toBytes(inputFilePath);

	for (size_t i = 0; i < 10000; i++) {
		imageBytes[55 + i] = 0;
	}

	AES model{ AESKeyLength::AES_128 };

	vector<BYTE> decryptedImage = model.decryptOFBImage(imageBytes, initVector, keyV);

	convertor.toImage(outputFilePath, decryptedImage);
}

vector<BYTE> stringTiVector(string& str) {
	vector<BYTE> vector(str.begin(), str.end());
	return vector;
}

//void test_128() {
//	string plaintext = "mamapapamamapapa";
//	//string plaintext = "hello my dear";
//	size_t bits = 128;
//	cout << "---------------------------------- (128) ----------------------------------" <<
//		endl << plaintext << endl << endl;
//
//	Tests test(plaintext, bits);
//
//	test.createECBCipherMap();
//	test.showCiphertextsMap();
//
//	test.doTests();
//}
//
void test_128_OFB() {
	string plaintext = "SomeSecretText";
	//string plaintext = "hello my dear";
	size_t bits = 128;
	cout << "---------------------------------- (128) ----------------------------------" <<
		endl << plaintext << endl << endl;

	Tests test(plaintext, bits);

	test.createOFBCipherMap();
	test.showCiphertextsMap();

	test.doTests();
}
//
//void test_192() {
//	string plaintext = "hello my name is ivan by";
//	size_t bits = 192;
//	cout << "\n\n" << "---------------------------------- (192) ----------------------------------" <<
//		endl << plaintext << endl << endl;
//
//	Tests test(plaintext, bits);
//
//	test.createECBCipherMap();
//	test.showCiphertextsMap();
//
//	test.doTests();
//}
//
//void test_256() {
//	string plaintext = "today we create tests for aes ya";
//	size_t bits = 256;
//	cout << "\n\n" << "---------------------------------- (256) ----------------------------------" <<
//		endl << plaintext << endl << endl;
//
//	Tests test(plaintext, bits);
//
//	test.createECBCipherMap();
//	test.showCiphertextsMap();
//
//	test.doTests();
//}

void testConsoleOutWithFreqOFB() {

	vector<BYTE> plaintextV = getPlaintext();

	string keyLength;
	cout << "Enter key lenght 128/192/256: " << endl;
	cin >> keyLength;

	AESKeyLength ks;

	if (keyLength == "128")
		ks = AESKeyLength::AES_128;
	else if (keyLength == "192")
		ks = AESKeyLength::AES_192;
	else if (keyLength == "256")
		ks = AESKeyLength::AES_256;

	vector<BYTE> keyV = generateKeyConstruct(keyLength);

	AES model{ks};

	vector<BYTE> ciphertextV = model.encryptWithFreqOFB(plaintextV, initVector, keyV);
	printVector(ciphertextV, "Ciphertext");
}

int main() {
	testConsoleOutWithFreqOFB();
	//test_128_OFB();
	
}

//2567687681024640768768768640512640640768384256896256768768102464076876876864051264064076838425689