#include "client_utils.h"

request_access_token_params *create_access_token_request(const char *id, const char *token, bool refresh) {

	request_access_token_params *req = (request_access_token_params *)malloc(sizeof(request_access_token_params));

	int len = strlen(id) + 1;
	req->id = (char *)malloc(len);
	memcpy(req->id, id, len);

	req->refresh = refresh;

	len = strlen(token) + 1;
	req->auth_token = (char *)malloc(len);
	memcpy(req->auth_token, token, len);

	return req;
}


request_resource_access_params *create_resource_access_request(const char *token, const char *resource, const char *operation) {

	request_resource_access_params *req = (request_resource_access_params *)malloc(sizeof(request_resource_access_params));
	
	int len = strlen(token) + 1;
	req->access_token = (char *)malloc(len);
	memcpy(req->access_token, token, len);

	len = strlen(resource) + 1;
	req->resource = (char *)malloc(len);
	memcpy(req->resource, resource, len);

	len = strlen(operation) + 1;
	req->operation = (char *)malloc(len);
	memcpy(req->operation, operation, len);

	return req;
}

request_refresh_params *create_refresh_request(const char *id, const char *token) {

	request_refresh_params *req = (request_refresh_params *)malloc(sizeof(request_refresh_params));

	int len = strlen(id) + 1;
	req->id = (char *)malloc(len);
	memcpy(req->id, id, len);

	len = strlen(token) + 1;
	req->refresh_token = (char *)malloc(len);
	memcpy(req->refresh_token, token, len);

	return req;
}

void free_access_token_request(request_access_token_params *req) {
	free(req->id);
	free(req->auth_token);
	free(req);
}

void free_resource_access_request(request_resource_access_params *req) {
	free(req->access_token);
	free(req->resource);
	free(req->operation);
	free(req);
}

void free_refresh_request(request_refresh_params *req) {
    free(req->id);
    free(req->refresh_token);
    free(req);
}

void print_request_resource_access(int status, bool refresh) {
	switch (status)
	{
		case PERMISSION_DENIED:
			cout << "PERMISSION_DENIED\n";
			break;
		case OPERATION_NOT_PERMITTED:
			cout << "OPERATION_NOT_PERMITTED\n";
			break;
		case PERMISSION_GRANTED:
			cout << "PERMISSION_GRANTED\n";
			break;
		case TOKEN_EXPIRED:
			if (!refresh)
				cout << "TOKEN_EXPIRED\n";
			break;
		case RESOURCE_NOT_FOUND:
			cout << "RESOURCE_NOT_FOUND\n";
			break;
		
		default:
			break;
	}

}

int request_resource_access(CLIENT* handle, const char *access_token, const char *resource, const char *operation, bool refresh) {

	//  request resource access
	request_resource_access_params *req = create_resource_access_request(access_token, resource, operation);
	resource_grant *resource_grant = request_resource_access_1(req, handle);
	free_resource_access_request(req);

    // print response
    print_request_resource_access(resource_grant->status, refresh);

	return resource_grant->status;
}