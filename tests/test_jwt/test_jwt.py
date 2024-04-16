import pytest

invalid_token = "e.ybmtZSJ9.tXJ9..."


@pytest.mark.asyncio
async def test_invalid_jwt_token(async_client):
    """
    Test invalid JWT token.
    """
    response = await async_client.get("/users/",
                                      headers={"Authorization": "Bearer "+invalid_token})
    assert response.status_code == 401
    assert response.headers.get("content-type") == "application/json"

@pytest.mark.asyncio
async def test_invalid_jwt_token_refresh(async_client):
    """
    Test invalid JWT token refresh.
    """
    response = await async_client.post("/token/refresh",
                                       headers={"Authorization": "Bearer "+invalid_token})
    assert response.status_code == 401

