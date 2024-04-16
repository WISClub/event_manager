"""
This Python file demonstrates the implementation of OAuth2 Password Flow in a FastAPI application. OAuth2 is a standard
protocol for authorization that enables applications to secure designated resources on behalf of a user. Specifically,
the Password Flow is suitable for trusted applications where the user provides their username and password directly to the
application, and in exchange, receives an access token to make authorized requests.

FastAPI simplifies the integration of OAuth2 by providing built-in tools and classes to manage authentication and token issuance.
This example will guide you through setting up an OAuth2PasswordBearer, which is a helper class provided by FastAPI to implement
the OAuth2 Password Flow, and creating endpoints for user authentication and token generation.

Understanding OAuth2PasswordBearer:
- OAuth2PasswordBearer is a class that FastAPI provides to handle OAuth2 Password Flow. It does not authenticate the user but
  specifies that the client (e.g., a frontend application) must send a token in the request's Authorization header using the Bearer scheme.
- The 'tokenUrl' parameter of OAuth2PasswordBearer indicates the URL where the client can send a username and password to obtain the token.

Workflow:
1. The client sends a username and password to the token endpoint.
2. The server authenticates the user with the provided credentials.
3. If authentication is successful, the server generates an access token and returns it to the client.
4. The client uses the access token for subsequent authorized requests to the server.
"""

# Import necessary modules and functions from FastAPI and the standard library
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPBearer
from datetime import timedelta
# Custom configuration settings loader
from app.dependencies import get_settings
# Import the Token schema from our application schemas
from app.schemas.token_schemas import Token, RefreshToken
import base64
import json
from app.utils.common import authenticate_user, create_access_token, create_refresh_token

# Load application settings
settings = get_settings()

# Initialize OAuth2PasswordBearer with the token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
http_bearer_scheme = HTTPBearer()

# Create an API router object for registering endpoint(s)
router = APIRouter()


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint to authenticate a user and issue an access token.

    Uses OAuth2PasswordRequestForm dependency to parse and validate the request form data (username and password).

    Args:
        form_data (OAuth2PasswordRequestForm): The form data containing the username and password.

    Returns:
        A JSON response containing the 'access_token' and 'token_type'.
    """

    # Authenticate the user with the provided credentials
    user = authenticate_user(form_data.username, form_data.password)

    # If authentication fails, return an HTTP 401 Unauthorized response
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Specify the duration the token will be valid
    access_token_expires = timedelta(
        minutes=settings.access_token_expire_minutes)

    # Generate an access token
    access_token = create_access_token(
        # 'sub' (subject) field to identify the user
        data={"sub": user["username"]},
        expires_delta=access_token_expires
    )

    # Return the access token and token type to the client
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/token/refresh", response_model=RefreshToken)
async def refresh_access_token(token: str = Depends(http_bearer_scheme)):
    """
    Endpoint to refresh an access token using a refresh token.

    Args:
        token (str): The refresh token provided by the client.

    Returns:
        A JSON response containing the 'refresh_token'.
    """

#    to implement refresh token logic
    # - Validate the refresh token
    # - Generate a new access token
    # - Return the new access token to the client

    def validate_refresh_token(token: str):
        try:
            # check if token is valid
            if not token:
                raise HTTPException(status_code=401, detail="Invalid token")

            def decode_token_to_payload(token: str):
                # todo: get the user and check if uuid is in db
                # Decode the token to payload
                payload = token.split('.')[1]
                # Apply padding. Add = until length is multiple of 4
                while len(payload) % 4 != 0:
                    payload += "="

                decoded_payload = base64.b64decode(payload)
                decoded_token = json.loads(decoded_payload.decode("utf-8"))
                return decoded_token
            decoded_token = decode_token_to_payload(token)
        except Exception as e:
            raise HTTPException(status_code=401, detail="Invalid token")
        return decoded_token
    token_data = validate_refresh_token(token.credentials)
    new = create_refresh_token(token_data)
    return {"refresh_token": str(token_data)}
