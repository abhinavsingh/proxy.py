/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
import { DashboardPlugin } from '../plugin'

export class HomePlugin extends DashboardPlugin {
  public name: string = 'home';
  public title: string = 'Home'

  public initializeTab () : JQuery<HTMLElement> {
    return this.makeTab('Home', 'fa-home')
  }

  public initializeHeader (): JQuery<HTMLElement> {
    return this.makeHeader(this.title)
  }

  // Show following metrics on home page:
  // 0. Uptime
  // 1. Total number of requests served counter
  //    - Separate numbers for proxy and in-built http server
  // 2. Number of active requests counter
  //    - Click to inspect via inspect traffic tab
  //    - Will be hard here to focus on exact active request within embedded Devtools
  // 3. Requests served per second / minute / hours chart
  // 4. Active requests per second / minute / hours chart
  // 5. List of all proxy.py processes
  //    - Threads per process
  //    - RAM / CPU per process over time charts
  // 6. Bandwidth served
  //    - Total incoming bytes
  //    - Total outgoing bytes
  //    - Ingress / Egress bytes per sec / min / hour
  // 7. Active plugin list
  public initializeBody (): JQuery<HTMLElement> {
    return $('<div></div>')
  }

  public activated (): void {}

  public deactivated (): void {}
}
