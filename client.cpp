#include <stdio.h>
#include <time.h> 
#include <rpc/rpc.h>
#include "auth.h"
#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
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


// void run(char* file) {

// 	FILE* input = fopen(file, "r+");

// 	if (!input) {
// 		fprintf(stderr, "ERROR: Couldn't open %s.\n", file);
// 		exit(EXIT_FAILURE);
// 	}
	
// 	map<string, string> cl;
// 	char* line = NULL;
// 	size_t len = 0;

// 	while ((getline(&line, &len, input)) != -1) {
// 		char* id = strtok(line, ",");
// 		char* op = strtok(NULL, ",");
// 		char* param = strtok(NULL, "\n");

// 		printf("%s %s %s\n", id, op, param);

// 		string id_str(id);

// 		if ()
// 		// 
// 		if (cl.find(id_str) == cl.end()) {

// 		}
// 	}

// 	fclose(input);
// }

struct Session{
  string auth_token;
  string access_token;
  bool refresh;
};

void run(CLIENT *handle, char *file) {
	fstream input(file);

	if (!input.is_open()) {
		fprintf(stderr, "ERROR: Couldn't open %s.\n", file);
		exit(EXIT_FAILURE);
	}

	map<string, Session> cl;
	string line;

	while (getline(input, line)) {
		vector<string> parts = split(line, ',');

		cout << parts[0] << " " << parts[1] << " " << parts[2] << endl;

		// request authorization
		if (!parts[1].compare("REQUEST")) {
			char *id = (char *)parts[0].c_str();

			auth_token *auth_token = request_authorization_1(&id, handle);

			if (strncmp(*auth_token, "USER_NOT_FOUND", strlen("USER_NOT_FOUND") + 1)) {
				cout << "PERMISSION_DENIED\n";
			} else {
				cout << "PERMISSION_GRANTED\n";
				string token(*auth_token);

				//  store session data for client
				cl.insert(parts[0], {token, NULL, !parts[2].compare("0") ? false : true});
			}
 
		} else {

		}
	}

	input.close();
}



int main(int argc, char **argv) {

	if (argc < 3) {
		fprintf(stderr, "USAGE: ./client <server addr> <file>\n");
		return -1;
	}

	CLIENT *handle = clnt_create(argv[1], AUTH_PROG, AUTH_VERS, "tcp");
	
	if (handle == NULL) {
		// Couldn't establish connection with server.
		clnt_pcreateerror(argv[1]);
		return -1;
	}

	run(handle, argv[2]);

	clnt_destroy(handle);
	return 0;
}
