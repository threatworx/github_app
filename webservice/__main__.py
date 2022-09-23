import asyncio
import os
import sys
import traceback


import aiohttp
from aiohttp import web
import cachetools
from gidgethub import aiohttp as gh_aiohttp
from gidgethub import routing
from gidgethub import sansio
from gidgethub import apps

from . import utils

router = routing.Router()
cache = cachetools.LRUCache(maxsize=500)

routes = web.RouteTableDef()
utils.set_requests_verify(os.path.dirname(os.path.realpath(__file__)) + os.sep + 'gd-ca-bundle.crt')

@routes.get("/create_github_app")
async def handle_get(request):
    print("In create_github_app handler")
    file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/github_app_config.html"
    with open(file_path, "r") as fd:
        fc = fd.read()
    fc = fc.replace("TW_STATE", utils.get_gh_app_manifest_state())
    return web.Response(headers={ "Content-Type": "text/html" }, body=fc)

@routes.get("/redirect")
async def redirect_handler(request):
    try:
        print("In redirect handler")
        #print(request.query)
        config = utils.get_config()
        if config['github_app'].getboolean('setup_done'):
            print("Error Ignoring additional redirect handler call as GitHub App is already setup")
            return web.Response(status=200, text="GitHub App is already setup")
        code = request.query['code']
        state = request.query['state']
        if state != utils.get_gh_app_manifest_state():
            print("Error security state mismatch, possible CSRF attack")
            return web.Response(status=200, text="Error security state mismatch, possible CSRF attack")
        api_url = "https://api.github.com/app-manifests/%s/conversions" % code
        response = utils.requests_post(api_url, { "Accept": "application/vnd.github+json" }, { }, True)
        response = response.json()
        #print(response)
        app_id = str(response['id'])
        private_key = response['pem']
        webhook_secret = response['webhook_secret']
        config['github_app']['app_id'] = app_id
        config['github_app']['private_key'] = private_key
        config['github_app']['webhook_secret'] = webhook_secret
        config['github_app']['setup_done'] = 'true'
        utils.write_config(config)
        config = utils.get_config(True)
        print("Updated GitHub App Configuration")
        return web.Response(status=200, text="Your GitHub App is installed successfully!")
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return web.Response(status=500)

@routes.post("/webhook")
async def webhook(request):
    try:
        body = await request.read()
        config = utils.get_config()
        secret = config['github_app']['webhook_secret']
        event = sansio.Event.from_http(request.headers, body, secret=secret)
        if event.event == "ping":
            return web.Response(status=200)
        async with aiohttp.ClientSession() as session:
            gh = gh_aiohttp.GitHubAPI(session, "threatworx", cache=cache)

            await asyncio.sleep(1)
            await router.dispatch(event, gh)
        try:
            print("GH requests remaining:", gh.rate_limit.remaining)
        except AttributeError:
            pass
        return web.Response(status=200)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return web.Response(status=500)

@router.register("pull_request", action="opened")
@router.register("pull_request", action="reopened")
async def pull_request_opened(event, gh, *args, **kwargs):
    print("In pull_request opened webhook")
    await utils.process_pull_request(event.data)

if __name__ == "__main__":  # pragma: no cover
    app = web.Application()

    app.router.add_routes(routes)
    config = utils.get_config()
    port = config['github_app']['port']
    if port is not None:
        port = int(port)
    else:
        port = 80
    web.run_app(app, port=port)

