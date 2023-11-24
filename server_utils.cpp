#include "server_utils.h"
#include "utils.h"

set<string> users_id;
set<string> resources;
queue<map<string, string>> approvals;

//  checks if id is part of authorized user ids
bool id_is_valid(char *id) {
    return users_id.find(id) != users_id.end();
}

//  marks given token as signed
void sign_auth_token(char *token) {
    map<string, auth_serv_session>::iterator it = auth_serv_storage.begin();
    
    while (it != auth_serv_storage.end()) {
        if (!it->second.auth_token.compare(token)) {
            it->second.sign_auth_token();
            return;
        }
        it++;
    }
}

//  checks if given token was marked as signed
bool auth_token_is_signed(char* token) {
    map<string, auth_serv_session>::iterator it = auth_serv_storage.begin();
    
    while (it != auth_serv_storage.end()) {
        if (!it->second.auth_token.compare(token)) {
            return it->second.signedd;
        }
        it++;
    }

    return false;
}

//  binds auth token to user id => authorized user
void authorize(char *user_id, char *auth_token) {
    auth_serv_storage[user_id] = auth_serv_session(auth_token);
}

//  check if first accessible approval is not empty (*,-) 
bool token_is_approved() {
    map<string, string> perm = approvals.front();

    if (perm.begin() != perm.end())
        return true;

    //  no permissions
    return false; 
}

// returns first available permissions
map<string, string> assign_permissions() {
    //  no available perm
    if (approvals.empty()) {
        return map<string, string>();
    }

    // get permissions
    map<string, string> permissions = approvals.front();
    approvals.pop();

    return permissions;
}

char translate_operation(char *operation) {
	if (!strcmp(operation, "EXECUTE"))
        return 'X';
	return operation[0];
}

//  checks if operation can be performed on a certain resource
bool operation_is_permitted(char *resource, char *operation, res_serv_session session) {
    //  get given permissions for a resource 
    map<string, string>::iterator all_perm = session.permissions.find(resource);
    
    if (all_perm == session.permissions.end())
        return false;
    
    return all_perm->second.find(translate_operation(operation)) != string::npos;
}

// adds a refreshed access token to the resource server (removes the old one)
void update_access_token(string old_access_token, string new_access_token) {
    // keep assigned permission
    map<string, string> perm = res_server_storage[old_access_token].permissions;

    // old access token is no longer valid => erase it
    res_server_storage.erase(old_access_token);

    // add new access token
    res_server_storage[new_access_token] = res_serv_session(token_life_time, perm, true);
}

//  loads input data to server
void load(int argc, char **argv) {

    if (argc < 5) {
		fprintf(stderr, "USAGE: ./server <file0> <file1> <file2> <token_life_time>\n");
		exit(EXIT_FAILURE);
	}

    fstream users(argv[1]);
    fstream res(argv[2]);
    fstream app(argv[3]);
    
    token_life_time = atoi(argv[4]);


    if (!users.is_open()) {
        fprintf(stderr, "ERROR: Couldn't open %s.\n", argv[1]);
		exit(EXIT_FAILURE);
    }

    if (!res.is_open()) {
        fprintf(stderr, "ERROR: Couldn't open %s.\n", argv[1]);
		exit(EXIT_FAILURE);
    }

    if (!app.is_open()) {
        fprintf(stderr, "ERROR: Couldn't open %s.\n", argv[1]);
		exit(EXIT_FAILURE);
    }

    //  load authorized users
    int no_users;
    users >> no_users;

    // get ids
    for (int i = 0; i < no_users; ++i) {
        string id;
        users >> id;
        users_id.insert(id);
    }

    users.close();

    //  load server resources
    int no_res;
    res >> no_res;

    // get resources
    for (int i = 0; i < no_users; ++i) {
        string res_name;
        res >> res_name;
        resources.insert(res_name);
    }

    res.close();

    //  load server approvals
    string line;
	while (getline(app, line)) {
		vector<string> parts = split(line, ',');

        map<string, string> approval;

        if (parts[0].compare("*")) {
            for (int i = 0; i < parts.size(); i += 2)
                approval[parts[i]] = parts[i + 1];
        }

        approvals.push(approval);
	}

    app.close();
}
