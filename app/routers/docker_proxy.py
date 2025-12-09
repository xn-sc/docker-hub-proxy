from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse
import httpx
from app.services import proxy_manager, traffic_logger
import logging
from urllib.parse import urlparse

router = APIRouter()
logger = logging.getLogger("docker_proxy")

# Standard Docker Hub Auth URL
DOCKER_AUTH_URL = "https://auth.docker.io/token"

async def stream_response(response: httpx.Response):
    async for chunk in response.aiter_bytes():
        traffic_logger.log_traffic(bytes_downloaded=len(chunk))
        yield chunk

@router.get("/token")
async def proxy_token(request: Request):
    """
    Proxy the auth token request to Docker Hub Auth.
    """
    # Construct upstream URL
    url = DOCKER_AUTH_URL
    if request.url.query:
        url += f"?{request.url.query}"

    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers)
            
            # Log upload traffic (minimal for token)
            traffic_logger.log_traffic(bytes_uploaded=len(request.url.query)) # Rough approx

            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=dict(resp.headers)
            )
    except Exception as e:
        logger.error(f"Token proxy error: {e}")
        return Response(content="Auth Error", status_code=500)

import re

# ... existing imports ...

async def parse_www_authenticate(header: str):
    """Parse Www-Authenticate header to extract realm, service, and scope."""
    # Example: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull"
    info = {}
    for key in ["realm", "service", "scope"]:
        match = re.search(f'{key}="([^"]+)"', header)
        if match:
            info[key] = match.group(1)
    return info

async def get_upstream_token(realm: str, service: str, scope: str, username: str, password: str) -> str:
    """Fetch Bearer token from upstream realm."""
    params = {}
    if service:
        params["service"] = service
    if scope:
        params["scope"] = scope
    
    try:
        # Docker auth usually uses Basic Auth to get the token
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(realm, params=params, auth=(username, password))
            if resp.status_code == 200:
                data = resp.json()
                return data.get("token") or data.get("access_token")
            else:
                logger.error(f"Failed to get token from {realm}: {resp.status_code} - {resp.text}")
                return None
    except Exception as e:
        logger.error(f"Token fetch error: {e}")
        return None

async def proxy_v2(path: str, request: Request):
    # 1. Get Best Proxy Node
    proxy_node = proxy_manager.get_best_proxy()
    upstream_base = proxy_node.url
    
    # Ensure no trailing slash on base, lead slash on path handled by f-string logic
    upstream_url = f"{upstream_base.rstrip('/')}/v2/{path}"
    
    # Query params
    if request.url.query:
        upstream_url += f"?{request.url.query}"
    
    # Headers
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    
    # Remove local Authorization if we are going to manage it, 
    # BUT for now, let's keep it. If upstream rejects it, we'll try our stored creds.
    # Actually, if we want to force our stored creds, we might want to strip it?
    # Let's strip it ONLY if we have stored creds and the first request fails? 
    # Or just let it fail first.
    
    # Body
    content = await request.body()
    traffic_logger.log_traffic(bytes_uploaded=len(content))

    client = httpx.AsyncClient(follow_redirects=True, timeout=None)
    
    async def send_request(url, head, body, auth=None):
        req = client.build_request(
            request.method,
            url,
            headers=head,
            content=body
        )
        if auth: # Manually add auth header if provided string
             req.headers["Authorization"] = auth
             
        return await client.send(req, stream=True)

    try:
        # First attempt (Transparency)
        r = await send_request(upstream_url, headers, content)
        
        # Check for 401 and if we have credentials to fix it
        if r.status_code == 401 and proxy_node.username and proxy_node.password:
            auth_header = r.headers.get("www-authenticate")
            if auth_header and "Bearer" in auth_header:
                # Close previous stream
                await r.aclose()
                
                logger.info(f"Upstream 401, attempting auth for {proxy_node.name}")
                auth_info = await parse_www_authenticate(auth_header)
                if auth_info.get("realm"):
                    token = await get_upstream_token(
                        auth_info["realm"], 
                        auth_info.get("service"), 
                        auth_info.get("scope"),
                        proxy_node.username,
                        proxy_node.password
                    )
                    
                    if token:
                        logger.info("Got upstream token, retrying request...")
                        # Retry with new token
                        # We must remove any existing Authorization header from original request
                        retry_headers = headers.copy()
                        retry_headers["Authorization"] = f"Bearer {token}"
                        r = await send_request(upstream_url, retry_headers, content)
                    else:
                        logger.warning("Failed to obtain upstream token.")
            
            elif r.status_code == 401 and "Basic" in auth_header:
                 # Basic Auth retry (Less common for Registry V2 but possible)
                 await r.aclose()
                 import base64
                 creds = f"{proxy_node.username}:{proxy_node.password}"
                 b64_creds = base64.b64encode(creds.encode()).decode()
                 retry_headers = headers.copy()
                 retry_headers["Authorization"] = f"Basic {b64_creds}"
                 r = await send_request(upstream_url, retry_headers, content)

    except Exception as e:
        await client.aclose()
        logger.error(f"Connection error: {e}")
        return Response(content=str(e), status_code=502)

    # Process Headers
    resp_headers = dict(r.headers)
    
    # Www-Authenticate Rewrite
    # If we successfully authenticated upstream, we might NOT want to send Www-Authenticate back to client?
    # If we return 200, client is happy.
    # If we return 401 (auth failed even with our creds), we should probably let client see it?
    # But we need to rewrite the Realm to point to us if we want client to be able to login against us?
    # Current logic: If we are here, r.status_code is the final result.
    
    auth_header = resp_headers.get("www-authenticate")
    if auth_header:
        my_host = f"{request.url.scheme}://{request.url.netloc}"
        import re
        realm_pattern = re.compile(r'realm="([^"]+)"')
        match = realm_pattern.search(auth_header)
        if match:
            upstream_realm = match.group(1)
            new_realm = f"{my_host}/token"
            resp_headers["www-authenticate"] = auth_header.replace(upstream_realm, new_realm)
    
    if request.method != "HEAD":
        resp_headers.pop("content-length", None)
    resp_headers.pop("content-encoding", None)

    async def iter_response():
        try:
            async for chunk in r.aiter_bytes():
                traffic_logger.log_traffic(bytes_downloaded=len(chunk))
                yield chunk
        finally:
            await r.aclose()
            await client.aclose()

    return StreamingResponse(
        iter_response(),
        status_code=r.status_code,
        headers=resp_headers
    )

# Explicitly handle /v2/ (root) for docker login checks
@router.api_route("/v2/", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_v2_root(request: Request):
    return await proxy_v2(path="", request=request)

# Handle subpaths
@router.api_route("/v2/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_v2_path(path: str, request: Request):
    return await proxy_v2(path=path, request=request)


