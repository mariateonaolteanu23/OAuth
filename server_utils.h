#include <stdio.h> 
#include <fstream>
#include <iostream>
#include <set>
#include <queue>
#include <map>
#include "auth.h"
#include "status.h"
#include "server_session.h"
using namespace std;

extern int token_life_time;

extern set<string> users_id;
extern set<string> resources;
extern queue<map<string, string>> approvals;

extern map<string, auth_serv_session> auth_serv_storage;
extern map<string, res_serv_session> res_server_storage;

bool id_is_valid(char *id);
void sign_auth_token(char *token);
bool auth_token_is_signed(char* token);
void authorize(char *user_id, char *auth_token);
map<string, string> assign_permissions();
bool token_is_approved();
bool operation_is_permitted(char *resource, char *operation, res_serv_session session);
void update_access_token(string old_access_token, string new_access_token);
void load(int argc, char **argv);