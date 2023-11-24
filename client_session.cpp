#include "client_session.h"

client_session::client_session() {}

client_session::client_session(string auth) {
    auth_token = auth;
}

client_session::client_session(string auth, string access) {
    auth_token = auth;
    access_token = access;
    granted_refresh = false;
}

void client_session::set_access_token(string access) {
    access_token = access;
}

void client_session::set_refresh_token(string refresh) {
    refresh_token = refresh;
}

void client_session::grant_refresh(string refresh) {
    refresh_token = refresh;
    granted_refresh = true;
}

