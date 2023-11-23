#include <stdio.h>
#include <time.h> 
#include <rpc/rpc.h>
#include "auth.h"
#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include "status.h"

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

struct session {
  string access_token;
  string refresh_token;
  bool refresh;
};

request_access_token_body *create_access_token_request(const char *id, const char *token, bool refresh) {

	request_access_token_body *req = (request_access_token_body *)malloc(sizeof(request_access_token_body));

	int len = strlen(id) + 1;
	req->user_id = (char *)malloc(len);
	memcpy(req->user_id, id, len);

	req->refresh = refresh;

	len = strlen(token) + 1;
	req->auth_token = (char *)malloc(len);
	memcpy(req->auth_token, token, len);

	return req;
}


request_resource_access_body *create_resource_access_request(const char *token, const char *resource, const char *operation) {

	request_resource_access_body *req = (request_resource_access_body *)malloc(sizeof(request_resource_access_body));

	int len = strlen(token) + 1;
	req->access_token = (char *)malloc(len);
	memcpy(req->access_token, token, len);

	len = strlen(resource) + 1;
	req->resource = (char *)malloc(len);
	memcpy(req->resource, resource, len);

	len = strlen(operation) + 1;
	req->operation = (char *)malloc(len);
	memcpy(req->operation, operation, len);

	return req;
}

void free_access_token_request(request_access_token_body *req) {
	free(req->user_id);
	free(req->auth_token);
	free(req);
}

void free_resource_access_request(request_resource_access_body *req) {
	free(req->access_token);
	free(req->resource);
	free(req->operation);
	free(req);
}

int request_resource_access(CLIENT* handle, const char *access_token, const char *resource, const char *operation, bool refresh) {
	request_resource_access_body *req = create_resource_access_request(access_token, resource, operation);
	resource_grant *resource_grant = request_resource_1(req, handle);

	//  print response for resource request
	switch (resource_grant->status)
	{
		case PERMISSION_DENIED:
			cout << "PERMISSION_DENIED\n";
			break;
		case OPERATION_NOT_PERMITTED:
			cout << "OPERATION_NOT_PERMITTED\n";
			break;
		case PERMISSION_GRANTED:
			cout << "PERMISSION_GRANTED\n";
			break;
		case TOKEN_EXPIRED:
			if (!refresh)
				cout << "TOKEN_EXPIRED\n";
			break;
		case RESOURCE_NOT_FOUND:
			cout << "RESOURCE_NOT_FOUND\n";
			break;
		
		default:
			break;
	}

	free_resource_access_request(req);
	return resource_grant->status;
}

void run(CLIENT *handle, char *file) {
	fstream input(file);

	if (!input.is_open()) {
		fprintf(stderr, "ERROR: Couldn't open %s.\n", file);
		exit(EXIT_FAILURE);
	}

	map<string, session> cl_sessions;
	string line;

	while (getline(input, line)) {
		vector<string> parts = split(line, ',');

		//cout << parts[0] << " " << parts[1] << " " << parts[2] << endl;

		// request authorization
		if (!parts[1].compare("REQUEST")) {
			char *id = (char *)parts[0].c_str();

			// REQUEST AUTH token
			auth_token_grant *auth_token_grant = request_authorization_token_1(&id, handle);

			if (auth_token_grant->status == USER_NOT_FOUND) {
				cout << "USER_NOT_FOUND\n";
			} else {
				//cout << "TOKEN " << string(auth_token_grant->auth_token_grant_u.auth_token)<< "\n";
				// APPROVE AUTH token
				auth_grant *auth_grant = approve_token_1(&auth_token_grant->auth_token_grant_u.auth_token, handle);

				bool refresh = !parts[2].compare("0") ? false : true;
				request_access_token_body *req = create_access_token_request(id, auth_token_grant->auth_token_grant_u.auth_token, refresh);

				//  REQUEST ACCESS token
				access_grant * access_grant = request_access_token_1(req, handle);

				if (access_grant->status == REQUEST_DENIED) {
					cout << "REQUEST_DENIED\n";
				} else {
					// store session data
					string auth_token = string(auth_token_grant->auth_token_grant_u.auth_token);
					string access_token, refresh_token;
					
					if (access_grant->status == REQUEST_APPROVED_REFRESH) {
						access_token = string(access_grant->access_grant_u.tokens.access_token);
						refresh_token = string(access_grant->access_grant_u.tokens.refresh_token);
						cout << auth_token << " -> " << access_token << "," << refresh_token <<"\n";
					} else {
						access_token = string(access_grant->access_grant_u.access_token);
						cout << auth_token << " -> " << access_token << "\n";
					}	
					
					cl_sessions[parts[0]] = {access_token, refresh_token, refresh};
				}

				free_access_token_request(req);
			}
			
		} else {
			map<string, session>::iterator it = cl_sessions.find(parts[0]);

			string access_token, refresh_token; 
			bool refresh = false;
			const char *resource = parts[2].c_str();
			const char *operation = parts[1].c_str();
		
			if (it == cl_sessions.end()) {
				access_token = "";
				refresh_token = "";
			} else {
				access_token = it->second.access_token;
				refresh_token = it->second.refresh_token;
				refresh = it->second.refresh;
			}

			int status = request_resource_access(handle, access_token.c_str(), resource, operation, refresh);

			//  access token is expired => try to refresh
			if (refresh && status == TOKEN_EXPIRED) {
				char *token = (char *)refresh_token.c_str();

				//  refresh access token
				refresh_grant *refresh_grant = request_refresh_token_1(&token, handle);

				if (refresh_grant->status == 0) {
					//  store new generated tokens
					it->second.access_token = refresh_grant->refresh_grant_u.tokens.access_token;
					it->second.refresh_token = refresh_grant->refresh_grant_u.tokens.refresh_token;

					//  retry resource access
					int status = request_resource_access(handle, refresh_grant->refresh_grant_u.tokens.access_token, 
																			resource, operation, false);
				}
			}
		}
	}

	input.close();
}



int main(int argc, char **argv) {

	if (argc < 3) {
		fprintf(stderr, "USAGE: ./client <server addr> <file>\n");
		exit(EXIT_FAILURE);
	}

	CLIENT *handle = clnt_create(argv[1], AUTH_PROG, AUTH_VERS, "tcp");
	
	if (handle == NULL) {
		// Couldn't establish connection with server.
		clnt_pcreateerror(argv[1]);
		exit(EXIT_FAILURE);
	}

	run(handle, argv[2]);

	clnt_destroy(handle);
	return 0;
}
