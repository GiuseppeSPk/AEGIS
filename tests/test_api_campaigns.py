"""API Campaign Tests."""

import pytest
from httpx import AsyncClient

# Test Data
EMAIL = "campaign_tester@example.com"
PASSWORD = "password123"
CAMPAIGN_DATA = {
    "name": "Test Campaign",
    "target_provider": "openai",
    "target_model": "gpt-4o",
    "attack_types": ["injection", "jailbreak"],
}


async def get_auth_token(client: AsyncClient) -> str:
    """Helper to register/login and get token."""
    await client.post(
        "/api/v1/auth/register",
        json={"email": EMAIL, "password": PASSWORD},
    )
    res = await client.post(
        "/api/v1/auth/login",
        data={"username": EMAIL, "password": PASSWORD},
    )
    return res.json()["access_token"]


@pytest.mark.asyncio
async def test_create_campaign(async_client: AsyncClient):
    """Test campaign creation."""
    token = await get_auth_token(async_client)
    headers = {"Authorization": f"Bearer {token}"}

    response = await async_client.post(
        "/api/v1/campaigns/",
        json=CAMPAIGN_DATA,
        headers=headers,
    )
    if response.status_code != 201:
        print(f"CREATE FAILED: {response.text}")

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == CAMPAIGN_DATA["name"]
    assert "id" in data
    assert data["status"] == "pending"


@pytest.mark.asyncio
async def test_list_campaigns(async_client: AsyncClient):
    """Test listing campaigns."""
    token = await get_auth_token(async_client)
    headers = {"Authorization": f"Bearer {token}"}

    # Create one
    await async_client.post(
        "/api/v1/campaigns/",
        json=CAMPAIGN_DATA,
        headers=headers,
    )

    # List
    response = await async_client.get(
        "/api/v1/campaigns/",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    # CampaignList model has 'campaigns' key
    assert "campaigns" in data
    assert data["total"] >= 1
    assert len(data["campaigns"]) >= 1
    assert data["campaigns"][0]["name"] == CAMPAIGN_DATA["name"]


@pytest.mark.asyncio
async def test_get_campaign(async_client: AsyncClient):
    """Test getting single campaign."""
    token = await get_auth_token(async_client)
    headers = {"Authorization": f"Bearer {token}"}

    # Create
    create_res = await async_client.post(
        "/api/v1/campaigns/",
        json=CAMPAIGN_DATA,
        headers=headers,
    )
    assert create_res.status_code == 201
    campaign_id = create_res.json()["id"]

    # Get
    response = await async_client.get(
        f"/api/v1/campaigns/{campaign_id}",
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["id"] == campaign_id
