#include "server_session.h"

//  RESOURCE SERVER
res_serv_session::res_serv_session() {}

res_serv_session::res_serv_session(int life, map<string, string> perm, bool refresh) {
    life_time = life;
    permissions = perm;
    refresh_granted = refresh;
}

//  AUTHORIZATION SERVER
auth_serv_session::auth_serv_session() {}

auth_serv_session::auth_serv_session(string auth) {
    auth_token = auth;
    signedd = false;
}

void auth_serv_session::set_access_token(string access) {
    access_token = access;
}

void auth_serv_session::set_refresh_token(string refresh) {
    refresh_token = refresh;
}

void auth_serv_session::sign_auth_token() {
    signedd = true;
}
