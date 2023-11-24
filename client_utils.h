#include <stdio.h>
#include <iostream>
#include "auth.h"
#include "client_session.h"
#include "status.h"

request_access_token_params *create_access_token_request(const char *id, const char *token, bool refresh);
request_resource_access_params *create_resource_access_request(const char *token, const char *resource, const char *operation);
request_refresh_params *create_refresh_request(const char *id, const char *token);

void free_access_token_request(request_access_token_params *req);
void free_resource_access_request(request_resource_access_params *req);
void free_refresh_request(request_refresh_params *req);

int request_resource_access(CLIENT* handle, const char *access_token, const char *resource, const char *operation, bool refresh);
