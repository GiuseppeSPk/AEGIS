"""API Authentication Tests."""

import pytest
from httpx import AsyncClient

# Test Data
EMAIL = "test@example.com"
PASSWORD = "password123"


@pytest.mark.asyncio
async def test_register(async_client: AsyncClient):
    """Test user registration."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={"email": EMAIL, "password": PASSWORD},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == EMAIL
    assert "id" in data
    assert data["tier"] == "free"


@pytest.mark.asyncio
async def test_login(async_client: AsyncClient):
    """Test user login."""
    # First register
    await async_client.post(
        "/api/v1/auth/register",
        json={"email": EMAIL, "password": PASSWORD},
    )

    # Then login
    response = await async_client.post(
        "/api/v1/auth/login",
        data={"username": EMAIL, "password": PASSWORD},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_get_me(async_client: AsyncClient):
    """Test get current user endpoint."""
    # Register & Login
    await async_client.post(
        "/api/v1/auth/register",
        json={"email": EMAIL, "password": PASSWORD},
    )
    login_res = await async_client.post(
        "/api/v1/auth/login",
        data={"username": EMAIL, "password": PASSWORD},
    )
    token = login_res.json()["access_token"]

    # Get Me
    response = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "user_id" in data
    assert data["auth_method"] == "jwt"


@pytest.mark.asyncio
async def test_duplicate_register(async_client: AsyncClient):
    """Test duplicate registration fails."""
    # First registration
    await async_client.post(
        "/api/v1/auth/register",
        json={"email": EMAIL, "password": PASSWORD},
    )
    
    # Second registration
    response = await async_client.post(
        "/api/v1/auth/register",
        json={"email": EMAIL, "password": PASSWORD},
    )
    assert response.status_code == 400
