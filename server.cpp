#include <stdio.h> 
#include <time.h> 
#include <rpc/rpc.h>
#include "auth.h"
#include "token.h"

char ** request_access_token_1_svc(char **id, struct svc_req *) {
    char* token = generate_access_token(*id);
    return &token;
}

auth_token * request_authorization_1_svc(char **id, struct svc_req *) {
    printf("BEGIN %s AUTHZ\n", *id);

    // get authorization token
    static char* token = generate_access_token(*id);

    return &token;
}