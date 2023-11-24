// request auth status
#define USER_FOUND 0
#define USER_NOT_FOUND -1

// request approval status
#define APPROVED 0
#define DENIED -1

// request access token (refresh) status
#define REQUEST_APPROVED_ACCESS 0
#define REQUEST_APPROVED_ACCESS_REFRESH 1
#define REQUEST_DENIED -1

// validate resource action/operation status
#define PERMISSION_GRANTED 0
#define PERMISSION_DENIED -1
#define TOKEN_EXPIRED -2
#define RESOURCE_NOT_FOUND -3
#define OPERATION_NOT_PERMITTED -4

// request refresh status
#define REFRESH_GRANTED 0
#define REFRESH_DENIED -1