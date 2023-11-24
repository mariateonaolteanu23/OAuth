#include <vector>
#include <string>
using namespace std;

vector<string> split(string str, char delim) {
	vector<string> parts;
	int start = 0;
	int size = str.size();

	for (int i = 0; i < size; ++i) {
		if (str[i] == delim) {
			parts.push_back(str.substr(start, i - start));
			start = i + 1;
		}
	}

	if (start != size)
		parts.push_back(str.substr(start, size - start));

	return parts;
}
