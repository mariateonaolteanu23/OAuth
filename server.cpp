#include <stdio.h> 
#include <time.h> 
#include <rpc/rpc.h>
#include <iostream>
#include <map>
#include "token.h"
#include "server_utils.h"

using namespace std;

int token_life_time;

map<string, auth_serv_session> auth_serv_storage;
map<string, res_serv_session> res_server_storage;


auth_token_grant *request_authorization_token_1_svc(id *id, struct svc_req *req) {
    static auth_token_grant auth_token_grant;
    cout << "BEGIN " << *id << " AUTHZ\n";

    if (id_is_valid(*id)) {
        // free previous grant
        xdr_free((xdrproc_t)xdr_auth_token_grant, (void *)&auth_token_grant);
        
        // generate auth token
        char* gen_auth_token = generate_access_token(*id);

        // associate authorization token to user
        authorize(*id, gen_auth_token);

        // grant authorization token
        auth_token_grant.status = USER_FOUND;
        auth_token_grant.auth_token_grant_u.auth_token = strdup(gen_auth_token);
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


access_grant *request_access_token_1_svc(request_access_token_params *data, struct svc_req *req) {
    static access_grant access_grant;

    cout << "  RequestToken = " << data->auth_token << "\n";

    //  assign permissions
    map<string, string> permissions = assign_permissions();

    if (auth_token_is_signed(data->auth_token)) {
        xdr_free((xdrproc_t)xdr_access_grant, (void *)&access_grant);

        //  generate access token
        char *access_token = generate_access_token(data->auth_token);
        cout << "  AccessToken = " << access_token << "\n";

        // assign access token to auth user
        auth_serv_storage[data->id].set_access_token(access_token);
        
        // auth server -> res server : resource owner interacts with the authorization server to grant access
        res_server_storage[access_token] = res_serv_session(token_life_time, permissions, data->refresh);

        // generate refresh token
        if (data->refresh) {
            char *refresh_token = generate_access_token(access_token);
            cout << "  RefreshToken = " << refresh_token << "\n";

            auth_serv_storage[data->id].set_refresh_token(refresh_token);

            access_grant.access_grant_u.tokens.access_token = strdup(access_token);
            access_grant.access_grant_u.tokens.refresh_token = strdup(refresh_token);
            access_grant.status = REQUEST_APPROVED_ACCESS_REFRESH;
            return &access_grant;
        }

        access_grant.access_grant_u.access_token = strdup(access_token);
        access_grant.status = REQUEST_APPROVED_ACCESS;
        return &access_grant;
    }

    access_grant.status = REQUEST_DENIED;
    return &access_grant;
}

refresh_grant *request_refresh_token_1_svc(request_refresh_params *data, struct svc_req *req) {
    static refresh_grant refresh_grant;

    // authenticate user => get current auth session for user
    map<string, auth_serv_session>::iterator it = auth_serv_storage.find(data->id);

    // refresh token is valid
    if (it != auth_serv_storage.end() && !it->second.refresh_token.compare(data->refresh_token)) {
        cout << "BEGIN " << it->first << " AUTHZ REFRESH\n";
    
        string auth_token = it->second.auth_token;
        string old_access_token = it->second.access_token;
    
        // refresh tokens
        char *new_access_token = generate_access_token(data->refresh_token);
        cout << "  AccessToken = " << new_access_token << "\n";

        char *new_refresh_token = generate_access_token(new_access_token);
        cout << "  RefreshToken = " << new_refresh_token << "\n";

        // store new tokens
        it->second.set_access_token(new_access_token);
        it->second.set_refresh_token(new_refresh_token);

        // notify resource server of the update
        update_access_token(old_access_token, new_access_token);

        //  create response for client
        xdr_free((xdrproc_t)xdr_refresh_grant, (void *)&refresh_grant);

        refresh_grant.refresh_grant_u.tokens.access_token = strdup(new_access_token);
        refresh_grant.refresh_grant_u.tokens.refresh_token = strdup(new_refresh_token);

        refresh_grant.status = REFRESH_GRANTED;
        return &refresh_grant;
    }

    //  refresh token is invalid (doesn't exist) => auth server can't grant refresh
    refresh_grant.status = REFRESH_DENIED;
    return &refresh_grant;
}


void print_server_request_resource(bool success, char *token, char *resource, char *operation, int life) {
    cout << (success ? "PERMIT" : "DENY") << " (" << operation << "," << resource << "," << (token != NULL ? token : "") << "," << life << ")\n";
}

resource_grant *request_resource_access_1_svc(request_resource_access_params *data, struct svc_req *req) {
    static resource_grant resource_grant;

    xdr_free((xdrproc_t)xdr_resource_grant, (void *)&resource_grant);

    //  get access token's metadata
    map<string, res_serv_session>::iterator it = res_server_storage.find(data->access_token);

    //  access token is not valid (it doesn't exist) 
    if (it == res_server_storage.end()) {
        print_server_request_resource(false, NULL, data->resource, data->operation, 0);
        resource_grant.status = PERMISSION_DENIED;
        return &resource_grant;
    }

    // token expired
    if (it->second.life_time == 0) {
        //  user doesn't have a refresh grant
        if (!it->second.refresh_granted) {
            // remove access token
            res_server_storage.erase(data->access_token);

            // print error
            print_server_request_resource(false, NULL, data->resource, data->operation, 0);
        }
        resource_grant.status = TOKEN_EXPIRED;
        return &resource_grant;
    }

    // update token life time
    it->second.life_time--;

    // requested resource not found
    if (resources.find(data->resource) == resources.end()) {
        print_server_request_resource(false, data->access_token, data->resource, data->operation, it->second.life_time);
        resource_grant.status = RESOURCE_NOT_FOUND;
        return &resource_grant;
    }

    // user isn't allowed to perform given operation on given resource
    if (!operation_is_permitted(data->resource, data->operation, it->second)) {
        print_server_request_resource(false, data->access_token, data->resource, data->operation, it->second.life_time);
        resource_grant.status = OPERATION_NOT_PERMITTED;
        return &resource_grant;
    }
    
    // validate action
    print_server_request_resource(true, data->access_token, data->resource, data->operation, it->second.life_time);
    resource_grant.status = PERMISSION_GRANTED;
    return &resource_grant;
}


static void
auth_prog_1(struct svc_req *rqstp, SVCXPRT *transp)
{
	union {
		id request_authorization_token_1_arg;
		token approve_token_1_arg;
		request_access_token_params request_access_token_1_arg;
		request_refresh_params request_refresh_token_1_arg;
		request_resource_access_params request_resource_access_1_arg;
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
		_xdr_argument = (xdrproc_t) xdr_request_access_token_params;
		_xdr_result = (xdrproc_t) xdr_access_grant;
		local = (char *(*)(char *, struct svc_req *)) request_access_token_1_svc;
		break;

	case REQUEST_REFRESH_TOKEN:
		_xdr_argument = (xdrproc_t) xdr_request_refresh_params;
		_xdr_result = (xdrproc_t) xdr_refresh_grant;
		local = (char *(*)(char *, struct svc_req *)) request_refresh_token_1_svc;
		break;

	case REQUEST_RESOURCE_ACCESS:
		_xdr_argument = (xdrproc_t) xdr_request_resource_access_params;
		_xdr_result = (xdrproc_t) xdr_resource_grant;
		local = (char *(*)(char *, struct svc_req *)) request_resource_access_1_svc;
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
    SVCXPRT *transp;

    setbuf(stdout, NULL);

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

