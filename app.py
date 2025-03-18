import json
from starlette.config import Config
from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, RedirectResponse
from authlib.integrations.starlette_client import OAuth
from mcp.server.sse import SseServerTransport
from starlette.routing import Mount, Route
import anyio
import httpx
import mcp.types as types
from mcp.server.lowlevel import Server
config = Config('.env')
oauth = OAuth(config)

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'

oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account',  # force to select account
    }
)
client = oauth.google

sse = SseServerTransport("/messages/")
app = Server("mcp-website-fetcher")


async def fetch_website(
    url: str,
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    headers = {
        "User-Agent": "MCP Test Server (github.com/modelcontextprotocol/python-sdk)"
    }
    async with httpx.AsyncClient(follow_redirects=True, headers=headers) as client:
        response = await client.get(url)
        response.raise_for_status()
        return [types.TextContent(type="text", text=response.text)]


@app.call_tool()
async def fetch_tool(
    name: str, arguments: dict
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    if name != "fetch":
        raise ValueError(f"Unknown tool: {name}")
    if "url" not in arguments:
        raise ValueError("Missing required argument 'url'")
    return await fetch_website(arguments["url"])


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="fetch",
            description="Fetches a website and returns its content",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch",
                    }
                },
            },
        )
    ]


async def homepage(request):
    user = request.session.get('user')
    access_token = request.headers.get('authorization')
    if access_token is not None:
        token = access_token.split(' ')[1]
        user = await oauth.google.userinfo(
            token={'access_token': token, 'token_type': 'bearer'})
    if user:
        data = json.dumps(user)
        html = (
            f'<pre>{data}</pre>'
            '<a href="/logout">logout</a>'
        )
        return HTMLResponse(html)
    return HTMLResponse('<a href="/login">login</a>')


async def login(request):
    redirect_uri = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, redirect_uri)


async def auth(request):
    token = await oauth.google.authorize_access_token(request)
    print(f"{token=}")
    user = token.get('userinfo')
    if user:
        request.session['user'] = user
    return RedirectResponse(url='/')


async def logout(request):
    request.session.pop('user', None)
    return RedirectResponse(url='/')


async def handle_sse(request):
    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await app.run(
            streams[0], streams[1], app.create_initialization_options()
        )


if __name__ == '__main__':
    import uvicorn
    starlette_app = Starlette(
        debug=True,
        routes=[
            Route("/", endpoint=homepage),
            Route("/login", endpoint=login),
            Route("/auth", endpoint=auth),
            Route("/logout", endpoint=logout),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message)
        ],
    )
    starlette_app.add_middleware(SessionMiddleware, secret_key="!secret")
    uvicorn.run(starlette_app, host='127.0.0.1', port=8000)
