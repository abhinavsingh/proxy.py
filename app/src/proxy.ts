/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

class ApiDevelopment {

    private specs: Map<string, Map<string, JSON>>;

    constructor() {
        this.fetchExistingSpecs();
    }

    private fetchExistingSpecs() {
        // TODO: Fetch list of currently configured APIs from the backend
        let apiExampleOrgSpec = new Map();
        apiExampleOrgSpec.set('/v1/users/', {
            'count': 2,
            'next': null,
            'previous': null,
            'results': [
                {
                    'email': 'you@example.com',
                    'groups': [],
                    'url': 'api.example.org/v1/users/1/',
                    'username': 'admin',
                },
                {
                    'email': 'someone@example.com',
                    'groups': [],
                    'url': 'api.example.org/v1/users/2/',
                    'username': 'someone',
                },
            ]
        });
        this.specs.set('api.example.org', apiExampleOrgSpec);
    }

}

export class ProxyDashboard {

    private hostname: string = 'localhost';
    private port: number = 8899;

    private ws: WebSocket;
    private ws_path: string = 'ws://' + this.hostname + ':' + this.port + '/app';

    private mid: number = 0;
    private last_ping_id: number;
    private last_ping_time: number;

    private readonly schedule_ping_every_ms: number = 1000;
    private readonly schedule_reconnect_every_ms: number = 5000;

    private server_ping_timer: number;
    private server_connect_timer: number;

    constructor() {
        $('#proxyTopNav>ul>li>a').on('click', switchTab);
        this.scheduleServerConnect(0);
    }

    private static getTime() {
        let date = new Date();
        return date.getTime();
    }

    private scheduleServerConnect(after_ms: number = this.schedule_reconnect_every_ms) {
        this.clearServerConnectTimer();
        this.server_connect_timer = window.setTimeout(
            this.connectToServer.bind(this), after_ms);
    }

    private connectToServer() {
        this.ws = new WebSocket(this.ws_path);
        this.ws.onopen = this.onServerWSOpen.bind(this);
        this.ws.onmessage = this.onServerWSMessage.bind(this);
        this.ws.onerror = this.onServerWSError.bind(this);
        this.ws.onclose = this.onServerWSClose.bind(this);
    }

    private onServerWSOpen(ev: MessageEvent) {
        this.clearServerConnectTimer();
        ProxyDashboard.setServerStatusSuccess('Connected...');
        this.scheduleServerPing(0);
    }

    private clearServerConnectTimer() {
        if (this.server_connect_timer == null) {
            return;
        }
        window.clearTimeout(this.server_connect_timer);
        this.server_connect_timer = null;
    }

    private onServerWSMessage(ev: MessageEvent) {
        let message = JSON.parse(ev.data);
        if (message.id == this.last_ping_id) {
            ProxyDashboard.setServerStatusSuccess(
                String((ProxyDashboard.getTime() - this.last_ping_time) + ' ms'));
            this.clearServerPingTimer();
            this.scheduleServerPing();
        }
    }

    private onServerWSError(ev: MessageEvent) {
        ProxyDashboard.setServerStatusDanger();
    }

    private onServerWSClose(ev: MessageEvent) {
        this.clearServerPingTimer();
        this.scheduleServerConnect();
        ProxyDashboard.setServerStatusDanger();
    }

    private scheduleServerPing(after_ms: number = this.schedule_ping_every_ms) {
        this.clearServerPingTimer();
        this.server_ping_timer = window.setTimeout(
            this.pingServer.bind(this), after_ms);
    }

    private clearServerPingTimer() {
        if (this.server_ping_timer != null) {
            window.clearTimeout(this.server_ping_timer);
            this.server_ping_timer = null;
        }
        this.last_ping_time = null;
        this.last_ping_id = null;
    }

    private pingServer() {
        this.last_ping_id = this.mid;
        this.last_ping_time = ProxyDashboard.getTime();
        this.mid++;
        // console.log('Pinging server with id:%d', this.last_ping_id);
        this.ws.send(JSON.stringify({'id': this.last_ping_id, 'method': 'ping'}));
    }

    private static setServerStatusDanger() {
        $('#proxyServerStatus').parent('div')
            .removeClass('text-success')
            .addClass('text-danger');
    }

    private static setServerStatusSuccess(summary: string) {
        $('#proxyServerStatus').parent('div')
            .removeClass('text-danger')
            .addClass('text-success');
        $('#proxyServerStatusSummary').text(
            '(' + summary + ')');
    }
}

// Outside of ProxyDashboard class since $(this.parentNode) usage complains about the
// parentNode attribute on ProxyDashboard class, even when switchTab is bound to the element.
function switchTab() {
    $('#proxyTopNav>ul>li.active').removeClass('active');
    $(this.parentNode).addClass('active');
    console.log('%s clicked', $(this).text().trim());
}

let proxyDashboard = new ProxyDashboard();
