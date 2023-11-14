#ifndef _IMG_CONV_
#define _IMG_CONV_

#include <vector>
#include <string>
#include <fstream>

using namespace std;

typedef unsigned char BYTE;

class IMG {
private:
	vector<BYTE> header;
	vector<BYTE> content;
public:
	vector<BYTE> toBytes(const string& path);
	string toImage(const string& path, vector<BYTE> input);
};

#endif // !_IMG_CONV_
