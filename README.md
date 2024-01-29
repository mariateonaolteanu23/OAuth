# OAuth

Implemented the OAuth protocol using RPC, providing flows for user authorization and resource access management. 

## Authorization

This process is handled by the `authorization server`. The server has the following functionalities:
- storing `session data` (id and tokens) about every authorized and authenticated user
- generating `access` and `refresh tokens`
- notifing the resource server about `granted access` (access tokens in use)

#### Workflows:
##### Authorization Grant
1. receive user's id 
2. exchange id with authorization token if the user is known

##### Access Token Grant
1. receive authorization token, user's id + refresh grant request (optional)
2. check if authorization token is signed
3. if the condition is met
    - determine permissions
    - generate access token
    - generate refresh token (if the user requested a refresh grant)
4. store session data
5. notify the resource server of the new access grant
    - the resource server should store the new access token and its metadata
6. grant the tokens

##### Refresh Token Grant
1. receive refresh token and user's id 
2. check if user is authorized and can refresh its access token
3. if yes, generate new tokens (access + refresh)
4. notify the resource server of the updated access grant
5. grant tokens
    
## Third-Party Approval
This process is simulated, using an approvals file. Based on the first available approval a set of permissions is assigned. If the permissions are invalid/empty then the authorization token of the user will not be marked as signed.

#### Workflow:
1. receive authorization token 
2. assign permissions
3. mark the given token according to the permissions

## Resource Access
This process is handled by the `resource server`. The server has the following functionalities:
- storing `session/metada data` (lifetime, refresh grant and permissions) about access tokens in use
- delegates resources

#### Workflow:
1. receive access token + operation and resource
2. check access token validity (is an active token)
3. check if the queried resource is available
4. check the access token's associated permissions
(is authorized to perform given operation on the resource)
5. grant or deny access to resource based on previous checks

## Notes
Modified the server stub in order to load input data at "boot time": moved stub logic in the main server file and added method for loading said data.

Added `setbuf(stdout, NULL)` in order to print server output.

