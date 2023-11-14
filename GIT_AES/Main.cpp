#include "AES.h"
#include "ImageConvertor.h"
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
	string inputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/cat.bmp";
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
	string inputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/cat.bmp";
	string middleFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/result.bmp";
	string outputFilePath = "C:/Users/ivmak/OneDrive/Рабочий стол/bmp/last.bmp";

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

	AES model{ AESKeyLength::AES_128 };

	vector<BYTE> decryptedImage = model.decryptOFBImage(imageBytes, initVector, keyV);

	convertor.toImage(outputFilePath, decryptedImage);
}

int main() {
	testConsoleOutOFB();
	//testConsoleOutECB();
	//pixelErrorTest();
}