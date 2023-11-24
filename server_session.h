#include <string>
#include <map>
#include <iostream>
using namespace std;

class res_serv_session {
    public:
        bool refresh_granted;
        int life_time;
        map<string, string> permissions;

        res_serv_session();
        res_serv_session(int life, map<string, string> perm, bool refresh);
};


class auth_serv_session {
    public:
        string auth_token;
        bool signedd;
        string access_token; 
        string refresh_token;

        auth_serv_session();
        auth_serv_session(string auth);

        void set_access_token(string access);
        void set_refresh_token(string refresh);
        void sign_auth_token();
};
