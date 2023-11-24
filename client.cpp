#include <stdio.h>
#include <time.h> 
#include <rpc/rpc.h>
#include <map>
#include <string>
#include <iostream>
#include <fstream>
#include "utils.h"
#include "client_utils.h"
using namespace std;


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

	fstream input(argv[2]);

	if (!input.is_open()) {
		fprintf(stderr, "ERROR: Couldn't open %s.\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	map<string, client_session> cl_sessions;
	string line;

	while (getline(input, line)) {
		vector<string> parts = split(line, ',');

		// REQUEST AUTHORIZATION: client <-> authorization server
		if (!parts[1].compare("REQUEST")) {

			char *id = (char *)parts[0].c_str();
			bool refresh = !parts[2].compare("0") ? false : true;

			// REQUEST AUTH token
			auth_token_grant *auth_token_grant = request_authorization_token_1(&id, handle);

			if (auth_token_grant->status == USER_NOT_FOUND) {
				cout << "USER_NOT_FOUND\n";
			} else {
				// APPROVE AUTH token
				auth_grant *auth_grant = approve_token_1(&auth_token_grant->auth_token_grant_u.auth_token, handle);

				//  REQUEST ACCESS token
				request_access_token_params *req = create_access_token_request(id, auth_token_grant->auth_token_grant_u.auth_token, refresh);
				access_grant * access_grant = request_access_token_1(req, handle);
				free_access_token_request(req);

				if (access_grant->status == REQUEST_DENIED) {
					cout << "REQUEST_DENIED\n";
				} else {
					// store session data
					cl_sessions[parts[0]] = client_session(auth_token_grant->auth_token_grant_u.auth_token, access_grant->access_grant_u.access_token);
					cout << auth_token_grant->auth_token_grant_u.auth_token << " -> " << access_grant->access_grant_u.access_token;

					// client can refresh access token
					if (access_grant->status == REQUEST_APPROVED_ACCESS_REFRESH) {
						cl_sessions[parts[0]].grant_refresh(access_grant->access_grant_u.tokens.refresh_token);
						cout << "," << access_grant->access_grant_u.tokens.refresh_token;
					}
					cout << "\n";
				}
			}
		
		//  REQUEST RESOURCE ACCESS: client <-> resource server
		} else {
			string access_token, refresh_token; 
			const char *resource = parts[2].c_str();
			const char *operation = parts[1].c_str();
			bool refresh = false;

			//  get client's session data
			map<string, client_session>::iterator it = cl_sessions.find(parts[0]);

			// client is authorized
			if (it != cl_sessions.end()) {
				access_token = it->second.access_token;
				refresh_token = it->second.refresh_token;
				refresh = it->second.granted_refresh;
			}

			// REQUEST resource access
			int status = request_resource_access(handle, access_token.c_str(), resource, operation, refresh);

			//  access token is expired => try to refresh
			if (refresh && status == TOKEN_EXPIRED) {
				//  REQUEST refresh
				request_refresh_params *req = create_refresh_request(parts[0].c_str(), refresh_token.c_str());
				refresh_grant *refresh_grant = request_refresh_token_1(req, handle);
				free_refresh_request(req);

				//  refresh request is approved
				if (refresh_grant->status == REFRESH_GRANTED) {
					//  store new generated tokens
					it->second.set_access_token(refresh_grant->refresh_grant_u.tokens.access_token);
					it->second.set_refresh_token(refresh_grant->refresh_grant_u.tokens.refresh_token);

					//  retry resource access
					int status = request_resource_access(handle, refresh_grant->refresh_grant_u.tokens.access_token, 
																			resource, operation, false);
				}
			}
		}
	}

	input.close();
	clnt_destroy(handle);
	return 0;
}
