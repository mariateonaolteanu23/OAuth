#include <string>
#include <map>
using namespace std;

class session_data {
    public:
        string refresh_token;
        int activity;
        map<string, string> permissions;

        session_data();
        session_data(int life, map<string, string> perm);
        session_data(string refresh, int life, map<string, string> perm);
};


