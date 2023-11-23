#include"session.h"

session_data::session_data() {}

session_data::session_data(string refresh, int life, map<string, string> perm) {
    refresh_token = refresh;
    activity = life;
    permissions = perm;
}

session_data::session_data(int life, map<string, string> perm) {
    refresh_token = {};
    activity = life;
    permissions = perm;
}
