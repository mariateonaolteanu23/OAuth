#include <stdio.h> 
#include <time.h> 
#include <rpc/rpc.h>
#include <fstream>
#include <iostream>
#include <set>
#include <queue>
#include <vector>
#include <map>
#include "auth.h"
#include "token.h"
#include "status.h"
#include "session.h"

using namespace std;

int token_life_time;
int no_users;

set<string> users_id;
set<string> resources;
queue<map<string, string>> approvals;


map<string, string> auth_serv_storage;
set<string> signed_auth_tokens;


map<string, session_data> res_server_storage;

//  checks if id is part of authorized user ids
bool id_is_valid(char *id) {
    return users_id.find(string(id)) != users_id.end();
}

//  marks given token as signed
void sign_auth_token(char *token) {
  signed_auth_tokens.insert(string(token));      
}

//  checks if given token was marked as signed
bool auth_token_is_signed(char* token) {
    return signed_auth_tokens.find(string(token)) != signed_auth_tokens.end();
}

void authorize(char *user_id, char *auth_token) {
    string id = string(user_id);
    string token = string(auth_token);
    
    map<string, string>::iterator it = auth_serv_storage.find(id);
    if (it == auth_serv_storage.end()) {
        auth_serv_storage[id] = string(token);
        return;
    }

    // erase prev token if it's signed
    if (signed_auth_tokens.find(it->second) !=  signed_auth_tokens.end())
        signed_auth_tokens.erase(it->second);

    // replace token
    it->second = token;
}

//  check if first accessible approval is not empty (*,-) 
bool token_is_approved() {
    map<string, string> perm = approvals.front();

    if (perm.begin() != perm.end())
        return true;

    //  no permissions
    return false; 
}

char translate_operation(char *operation) {
	if (!strcmp(operation, "EXECUTE"))
        return 'X';
	return operation[0];
}

bool operation_is_permitted(char *operation, string perm) {
    return perm.find(translate_operation(operation)) != string::npos;
}

auth_token_grant *request_authorization_token_1_svc(id *id, struct svc_req *req) {
    static auth_token_grant auth_token_grant;
    cout << "BEGIN " << *id << " AUTHZ\n";

    if (id_is_valid(*id)) {
        // free previous grant
        xdr_free((xdrproc_t)xdr_auth_token_grant, (void *)&auth_token_grant);
        
        // generate token
        char* gen_token = generate_access_token(*id);

        // associate authorization token to user
        authorize(*id, gen_token);

        // grant authorization token
        auth_token_grant.status = USER_FOUND;
        auth_token_grant.auth_token_grant_u.auth_token = strdup(gen_token);
        return &auth_token_grant;
    }

    auth_token_grant.status = USER_NOT_FOUND;
    return &auth_token_grant;
}

auth_grant *approve_token_1_svc(token *auth_token, struct svc_req * req) {
    static auth_grant auth_grant;

    xdr_free((xdrproc_t)xdr_auth_grant, (void *)&auth_grant);
    auth_grant.auth_grant_u.auth_token = strdup(*auth_token);

    if (token_is_approved()) {
        // mark auth token as signed
        sign_auth_token(*auth_token);

        auth_grant.status = APPROVED;        
        return &auth_grant;
    }

    auth_grant.status = DENIED;
    return &auth_grant;
}


access_grant *request_access_token_1_svc(request_access_token_body *data, struct svc_req *req) {
    static access_grant access_grant;

    cout << "  RequestToken = " << data->auth_token << "\n";

    //  get permissions
    if (approvals.empty()) {
        access_grant.status = REQUEST_DENIED;
        return &access_grant;
    }

    map<string, string> approved_op = approvals.front();
    approvals.pop();


    if (auth_token_is_signed(data->auth_token)) {
        xdr_free((xdrproc_t)xdr_access_grant, (void *)&access_grant);

        //  get access token
        char *access_token = generate_access_token(data->auth_token);
        cout << "  AccessToken = " << access_token << "\n";

        // get refresh token
        if (data->refresh) {
            char *refresh_token = generate_access_token(access_token);
            cout << "  RefreshToken = " << refresh_token << "\n";

            res_server_storage[string(access_token)] = session_data(string(refresh_token), token_life_time, approved_op);
            access_grant.access_grant_u.tokens.access_token = strdup(access_token);
            access_grant.access_grant_u.tokens.refresh_token = strdup(refresh_token);
            access_grant.status = REQUEST_APPROVED_REFRESH;
            return &access_grant;
        }

        res_server_storage[string(access_token)] = session_data(token_life_time, approved_op);
        access_grant.access_grant_u.access_token = strdup(access_token);
        access_grant.status = REQUEST_APPROVED;
        return &access_grant;
    }

    access_grant.status = REQUEST_DENIED;
    return &access_grant;
}

refresh_grant *request_refresh_token_1_svc(token *, struct svc_req *) {

    return NULL;
}


void print_server_request_resource(bool success, char *token, char *resource, char *operation, int life) {
    if (success) {
        cout << "PERMIT ";
    } else {
        cout << "DENY ";
    }

    cout << "(" << operation << "," << resource << "," << (token != NULL ? token : "") << "," << life << ")\n";
}

resource_grant *request_resource_1_svc(request_resource_access_body *data, struct svc_req *req) {
    static resource_grant resource_grant;

    xdr_free((xdrproc_t)xdr_resource_grant, (void *)&resource_grant);
    map<string, session_data>::iterator it = res_server_storage.find(string(data->access_token));

    //  access token is not valid (it doesn't exist) 
    if (it == res_server_storage.end()) {
        print_server_request_resource(false, NULL, data->resource, data->operation, 0);
        resource_grant.status = PERMISSION_DENIED;
        return &resource_grant;
    }

    // token expired
    if (it->second.activity == 0) {
        print_server_request_resource(false, NULL, data->resource, data->operation, 0);
        resource_grant.status = TOKEN_EXPIRED;
        return &resource_grant;
    }

    // update token life time
    it->second.activity--;

    // requested resource not found
    if (resources.find(data->resource) == resources.end()) {
        print_server_request_resource(false, data->access_token, data->resource, data->operation, it->second.activity);
        resource_grant.status = RESOURCE_NOT_FOUND;
        return &resource_grant;
    }

    string perm;
    map<string, string>::iterator all_perm = it->second.permissions.find(data->resource);
    
    if (all_perm != it->second.permissions.end()) {
        perm = all_perm->second;
    } else {
        perm = ""; 
    }

    if (!operation_is_permitted(data->operation, perm)) {
        print_server_request_resource(false, data->access_token, data->resource, data->operation, it->second.activity);
        resource_grant.status = OPERATION_NOT_PERMITTED;
        return &resource_grant;
    }
    
    print_server_request_resource(true, data->access_token, data->resource, data->operation, it->second.activity);
    resource_grant.status = PERMISSION_GRANTED;
    return &resource_grant;
}

vector<string> split(string str, char delim) {
	vector<string> parts;
	int start = 0;
	int size = str.size();

	for (int i = 0; i < size; ++i) {
		if (str[i] == delim) {
			parts.push_back(str.substr(start, i - start));
			start = i + 1;
		}
	}

	if (start != size)
		parts.push_back(str.substr(start, size - start));

	return parts;
}


void load(int argc, char **argv) {

    if (argc < 5) {
		fprintf(stderr, "USAGE: ./server <file0> <file1> <file2> <token_life_time>\n");
		exit(EXIT_FAILURE);
	}

    fstream users(argv[1]);
    fstream res(argv[2]);
    fstream app(argv[3]);
    
    token_life_time = atoi(argv[4]);


    if (!users.is_open()) {
        fprintf(stderr, "ERROR: Couldn't open %s.\n", argv[1]);
		exit(EXIT_FAILURE);
    }

    if (!res.is_open()) {
        fprintf(stderr, "ERROR: Couldn't open %s.\n", argv[1]);
		exit(EXIT_FAILURE);
    }

    if (!app.is_open()) {
        fprintf(stderr, "ERROR: Couldn't open %s.\n", argv[1]);
		exit(EXIT_FAILURE);
    }

    //  load authorized users
    users >> no_users;

    // get ids
    for (int i = 0; i < no_users; ++i) {
        string id;
        users >> id;
        users_id.insert(id);
    }

    users.close();

    //  load server resources
    int no_res;
    res >> no_res;

    // get resources
    for (int i = 0; i < no_users; ++i) {
        string res_name;
        res >> res_name;
        resources.insert(res_name);
    }

    res.close();

    //  load server approvals
    string line;
	while (getline(app, line)) {
		vector<string> parts = split(line, ',');

        map<string, string> approval;

        if (parts[0].compare("*")) {
            for (int i = 0; i < parts.size(); i += 2)
                approval[parts[i]] = parts[i + 1];
        }

        approvals.push(approval);
	}

    app.close();
}

static void
auth_prog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		id request_authorization_token_1_arg;
		token approve_token_1_arg;
		request_access_token_body request_access_token_1_arg;
		token request_refresh_token_1_arg;
		request_resource_access_body request_resource_1_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply (transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;

	case REQUEST_AUTHORIZATION_TOKEN:
		_xdr_argument = (xdrproc_t) xdr_id;
		_xdr_result = (xdrproc_t) xdr_auth_token_grant;
		local = (char *(*)(char *, struct svc_req *)) request_authorization_token_1_svc;
		break;

	case APPROVE_TOKEN:
		_xdr_argument = (xdrproc_t) xdr_token;
		_xdr_result = (xdrproc_t) xdr_auth_grant;
		local = (char *(*)(char *, struct svc_req *)) approve_token_1_svc;
		break;

	case REQUEST_ACCESS_TOKEN:
		_xdr_argument = (xdrproc_t) xdr_request_access_token_body;
		_xdr_result = (xdrproc_t) xdr_access_grant;
		local = (char *(*)(char *, struct svc_req *)) request_access_token_1_svc;
		break;

	case REQUEST_REFRESH_TOKEN:
		_xdr_argument = (xdrproc_t) xdr_token;
		_xdr_result = (xdrproc_t) xdr_refresh_grant;
		local = (char *(*)(char *, struct svc_req *)) request_refresh_token_1_svc;
		break;

	case REQUEST_RESOURCE:
		_xdr_argument = (xdrproc_t) xdr_request_resource_access_body;
		_xdr_result = (xdrproc_t) xdr_resource_grant;
		local = (char *(*)(char *, struct svc_req *)) request_resource_1_svc;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	return;
}

int
main (int argc, char **argv)
{
	setbuf(stdout, NULL);
    register SVCXPRT *transp;

	pmap_unset (AUTH_PROG, AUTH_VERS);

    load(argc, argv);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, AUTH_PROG, AUTH_VERS, auth_prog_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (AUTH_PROG, AUTH_VERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, AUTH_PROG, AUTH_VERS, auth_prog_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (AUTH_PROG, AUTH_VERS, tcp).");
		exit(1);
	}

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}