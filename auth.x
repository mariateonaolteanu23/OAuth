
typedef string auth_token<>;

program AUTH_PROG {
	version AUTH_VERS {
		auth_token REQUEST_AUTHORIZATION(string) = 1;
		string REQUEST_ACCESS_TOKEN(string) = 2;
	} = 1;
} = 223232323;
