/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

class ApiDevelopment {
  private specs: Map<string, Map<string, JSON>>;

  constructor () {
    this.specs = new Map()
    this.fetchExistingSpecs()
  }

  private fetchExistingSpecs () {
    // TODO: Fetch list of currently configured APIs from the backend
    const apiExampleOrgSpec = new Map()
    apiExampleOrgSpec.set('/v1/users/', {
      count: 2,
      next: null,
      previous: null,
      results: [
        {
          email: 'you@example.com',
          groups: [],
          url: 'api.example.org/v1/users/1/',
          username: 'admin'
        },
        {
          email: 'someone@example.com',
          groups: [],
          url: 'api.example.org/v1/users/2/',
          username: 'someone'
        }
      ]
    })
    this.specs.set('api.example.org', apiExampleOrgSpec)
  }
}

class WebsocketApi {
  private hostname: string = 'localhost';
  private port: number = 8899;
  private wsPrefix: string = '/dashboard';
  private wsScheme: string = 'ws';
  private ws: WebSocket;
  private wsPath: string = this.wsScheme + '://' + this.hostname + ':' + this.port + this.wsPrefix;

  private mid: number = 0;
  private lastPingId: number;
  private lastPingTime: number;

  private readonly schedulePingEveryMs: number = 1000;
  private readonly scheduleReconnectEveryMs: number = 5000;

  private serverPingTimer: number;
  private serverConnectTimer: number;

  constructor () {
    this.scheduleServerConnect(0)
  }

  private scheduleServerConnect (after_ms: number = this.scheduleReconnectEveryMs) {
    this.clearServerConnectTimer()
    this.serverConnectTimer = window.setTimeout(
      this.connectToServer.bind(this), after_ms)
  }

  private clearServerConnectTimer () {
    if (this.serverConnectTimer == null) {
      return
    }
    window.clearTimeout(this.serverConnectTimer)
    this.serverConnectTimer = null
  }

  private scheduleServerPing (after_ms: number = this.schedulePingEveryMs) {
    this.clearServerPingTimer()
    this.serverPingTimer = window.setTimeout(
      this.pingServer.bind(this), after_ms)
  }

  private clearServerPingTimer () {
    if (this.serverPingTimer != null) {
      window.clearTimeout(this.serverPingTimer)
      this.serverPingTimer = null
    }
    this.lastPingTime = null
    this.lastPingId = null
  }

  private onServerWSOpen (ev: MessageEvent) {
    this.clearServerConnectTimer()
    ProxyDashboard.setServerStatusSuccess('Connected...')
    this.scheduleServerPing(0)
  }

  private onServerWSMessage (ev: MessageEvent) {
    const message = JSON.parse(ev.data)
    if (message.id === this.lastPingId) {
      ProxyDashboard.setServerStatusSuccess(
        String((ProxyDashboard.getTime() - this.lastPingTime) + ' ms'))
      this.clearServerPingTimer()
      this.scheduleServerPing()
    } else {
      console.log(message)
    }
  }

  private onServerWSError (ev: MessageEvent) {
    ProxyDashboard.setServerStatusDanger()
  }

  private onServerWSClose (ev: MessageEvent) {
    this.clearServerPingTimer()
    this.scheduleServerConnect()
    ProxyDashboard.setServerStatusDanger()
  }

  private connectToServer () {
    this.ws = new WebSocket(this.wsPath)
    this.ws.onopen = this.onServerWSOpen.bind(this)
    this.ws.onmessage = this.onServerWSMessage.bind(this)
    this.ws.onerror = this.onServerWSError.bind(this)
    this.ws.onclose = this.onServerWSClose.bind(this)
  }

  private pingServer () {
    this.lastPingId = this.mid
    this.lastPingTime = ProxyDashboard.getTime()
    this.mid++
    // console.log('Pinging server with id:%d', this.last_ping_id);
    this.ws.send(JSON.stringify({ id: this.lastPingId, method: 'ping' }))
  }

  private enableInspection () {
    this.ws.send(JSON.stringify({ id: this.mid, method: 'enable_inspection' }))
    this.mid++
  }

  private disableInspection () {
    this.ws.send(JSON.stringify({ id: this.mid, method: 'disable_inspection' }))
    this.mid++
  }
}

export class ProxyDashboard {
  private websocketApi: WebsocketApi
  private apiDevelopment: ApiDevelopment

  constructor () {
    this.websocketApi = new WebsocketApi()
    $('#proxyTopNav>ul>li>a').on('click', function () {
      ProxyDashboard.switchTab(this)
    })
    this.apiDevelopment = new ApiDevelopment()
  }

  public static getTime () {
    const date = new Date()
    return date.getTime()
  }

  public static setServerStatusDanger () {
    $('#proxyServerStatus').parent('div')
      .removeClass('text-success')
      .addClass('text-danger')
  }

  public static setServerStatusSuccess (summary: string) {
    $('#proxyServerStatus').parent('div')
      .removeClass('text-danger')
      .addClass('text-success')
    $('#proxyServerStatusSummary').text(
      '(' + summary + ')')
  }

  // Outside of ProxyDashboard class since $(this.parentNode) usage complains about the
  // parentNode attribute on ProxyDashboard class, even when switchTab is bound to the element.
  private static switchTab (element: HTMLElement) {
    $('#proxyTopNav>ul>li.active').removeClass('active')
    $(element.parentNode).addClass('active')
    console.log('%s clicked, id %s', $(element).text().trim(), $(element).attr('id'))
  }
}

(window as any).ProxyDashboard = ProxyDashboard
