
typedef string token<>;
typedef string id<>;

union auth_token_grant switch(int status) {
	case 0:
		token auth_token;
	default:
		void;
};

union auth_grant switch(int status) {
	case 0:
		token auth_token;
	default:
		void;
};

struct request_access_token_params {
	id id;
	token auth_token;
	bool refresh;
};

struct bearer_tokens {
	token access_token;
	token refresh_token;
};

union access_grant switch(int status) {
	case 0:
		token access_token;
	case 1:
		bearer_tokens tokens;
	default:
		void;
};

struct request_refresh_params {
	id id;
	token refresh_token;
};

union refresh_grant switch(int status) {
	case 0:
		bearer_tokens tokens;
	default:
		void;
};

struct request_resource_access_params {
	token access_token;
	string resource<>;
	string operation<>; 
};

struct resource_grant {
	int status;
};

program AUTH_PROG {
	version AUTH_VERS {
		auth_token_grant REQUEST_AUTHORIZATION_TOKEN(id) = 1;
		auth_grant APPROVE_TOKEN(token) = 2;
		access_grant REQUEST_ACCESS_TOKEN(request_access_token_params) = 3;
		refresh_grant REQUEST_REFRESH_TOKEN(request_refresh_params) = 4;
		resource_grant REQUEST_RESOURCE_ACCESS(request_resource_access_params) = 5;
	} = 1;
} = 223232323;
