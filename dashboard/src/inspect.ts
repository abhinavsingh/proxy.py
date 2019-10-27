export class WebsocketApi {
    private name:string = "proxyInspect"
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
  
    private inspectionEnabled: boolean;
  
    constructor () {
      this.scheduleServerConnect(0)
    }
  
    public enableInspection () {
      // TODO: Set flag to true only once response has been received from the server
      this.inspectionEnabled = true
      this.ws.send(JSON.stringify({ id: this.mid, method: 'enable_inspection' }))
      this.mid++
    }
  
    public disableInspection () {
      this.inspectionEnabled = false
      this.ws.send(JSON.stringify({ id: this.mid, method: 'disable_inspection' }))
      this.mid++
    }
  
    private scheduleServerConnect (after_ms: number = this.scheduleReconnectEveryMs) {
      this.clearServerConnectTimer()
      this.serverConnectTimer = window.setTimeout(
        this.connectToServer.bind(this), after_ms)
    }
  
    private connectToServer () {
      this.ws = new WebSocket(this.wsPath)
      this.ws.onopen = this.onServerWSOpen.bind(this)
      this.ws.onmessage = this.onServerWSMessage.bind(this)
      this.ws.onerror = this.onServerWSError.bind(this)
      this.ws.onclose = this.onServerWSClose.bind(this)
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
  
    private pingServer () {
      this.lastPingId = this.mid
      this.lastPingTime = ProxyDashboard.getTime()
      this.mid++
      // console.log('Pinging server with id:%d', this.last_ping_id);
      this.ws.send(JSON.stringify({ id: this.lastPingId, method: 'ping' }))
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

    
     

    public enable(){
      
      this.enableInspection();
      $("#"+ this.name +"Section").show();
    }
    
    public disable(){
      this.disableInspection();
      $("#"+ this.name + "Section").hide();
    }

    
  }