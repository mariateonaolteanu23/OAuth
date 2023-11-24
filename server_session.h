#include <string>
#include <map>
#include <iostream>
using namespace std;

//  RESOURCE SERVER
class res_serv_session {
    public:
        bool refresh_granted;            // access token property to be refreshed
        int lifetime;                    // access token validity
        map<string, string> permissions; // perm assigned to the access token

        res_serv_session();
        res_serv_session(int life, map<string, string> perm, bool refresh);
};

//  AUTHORIZATION SERVER
class auth_serv_session {
    public:
        string auth_token;              // user's authorization token
        bool signedd;                   // user has/doesn't have approval
        string access_token;            // user's access token
        string refresh_token;           // user's refresh token

        auth_serv_session();
        auth_serv_session(string auth);

        void set_access_token(string access);
        void set_refresh_token(string refresh);
        void sign_auth_token();
};
