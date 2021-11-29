from blacksheep.server import Application
from blacksheep.server.responses import text


app = Application()


@app.route('/http-route-example')
async def home(request):
    return text('HTTP route response')
