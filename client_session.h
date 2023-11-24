#include <string>
using namespace std;

class client_session {
    public:
        string auth_token;
        string access_token; 
        string refresh_token;
        bool granted_refresh;

        client_session();
        client_session(string auth);
        client_session(string auth, string access);

        void set_access_token(string access);
        void set_refresh_token(string refresh);
        void grant_refresh(string refresh);
};