class ProxyDashboard {

    private hostname: string = 'localhost';
    private port: number = 8899;

    private ws: WebSocket;
    private ws_path: string = 'ws://' + this.hostname + ':' + this.port + '/app';

    private mid: number = 0;
    private last_ping_id: number;

    private server_ping_timer: number;
    private server_connect_timer: number;

    constructor() {
        $('#proxyTopNav>ul>li>a').on('click', switchTab);
        this.scheduleServerConnect(0);
    }

    private scheduleServerConnect(after_ms: number = 5000) {
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
        ProxyDashboard.setServerStatusSuccess();
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
            this.server_ping_timer = null;
            this.last_ping_id = null;
            ProxyDashboard.setServerStatusSuccess();
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

    private scheduleServerPing(after_ms: number = 5000) {
        this.clearServerPingTimer();
        this.server_ping_timer = window.setTimeout(
            this.pingServer.bind(this), after_ms);
    }

    private clearServerPingTimer() {
        if (this.server_ping_timer != null) {
            window.clearTimeout(this.server_ping_timer);
            this.server_ping_timer = null;
        }
    }

    private pingServer() {
        this.last_ping_id = this.mid;
        // console.log('Pinging server with id:%d', this.last_ping_id);
        this.mid++;
        this.ws.send(JSON.stringify({'id': this.last_ping_id, 'method': 'ping'}));
    }

    private static setServerStatusDanger() {
        $('#proxyServerStatus').parent('div')
            .removeClass('text-success')
            .addClass('text-danger');
    }

    private static setServerStatusSuccess() {
        $('#proxyServerStatus').parent('div')
            .removeClass('text-danger')
            .addClass('text-success');
    }
}

let proxyDashboard = new ProxyDashboard();

function switchTab() {
    $('#proxyTopNav>ul>li.active').removeClass('active');
    $(this.parentNode).addClass('active');
    console.log('%s clicked', $(this).text().trim());
}
