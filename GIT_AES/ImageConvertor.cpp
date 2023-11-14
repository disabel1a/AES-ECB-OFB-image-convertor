#include "ImageConvertor.h"

vector<BYTE> IMG::toBytes(const string& path)
{
	ifstream file(path, std::ios::binary);
	if (!file) {
		throw std::runtime_error("File reader error: " + path);
	}

	const size_t headerSize = 54;
	header.resize(headerSize);

	file.read(reinterpret_cast<char*>(header.data()), headerSize);

	file.seekg(0, std::ios::end);
	const size_t fileSize = file.tellg();
	const size_t contentSize = fileSize - headerSize;

	content.resize(contentSize);
	file.seekg(headerSize);
	file.read(reinterpret_cast<char*>(content.data()), contentSize);

	file.close();

	return content;
}

string IMG::toImage(const string& path, vector<BYTE> input)
{
	vector<uint8_t> combBytes(header);
	combBytes.insert(combBytes.end(), input.begin(), input.end());

	ofstream file(path, std::ios::binary);

	if (file) {
		file.write(reinterpret_cast<const char*>(combBytes.data()), combBytes.size());
		file.close();
		return path;
	}
	else {
		throw std::runtime_error("File reader error: " + path);
	}
}
