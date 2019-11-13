/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
import { DashboardPlugin } from '../plugin'

declare const Root: any

export class InspectTrafficPlugin extends DashboardPlugin {
  public name: string = 'inspect_traffic'
  public title: string = 'Inspect Traffic'

  public initializeTab () : JQuery<HTMLElement> {
    return this.makeTab(this.title, 'fa-binoculars')
  }

  public initializeHeader (): JQuery<HTMLElement> {
    return this.makeHeader(this.title)
  }

  public initializeBody (): JQuery<HTMLElement> {
    return $('')
  }

  public activated (): void {
    this.websocketApi.enableInspection(this.handleEvents.bind(this))
  }

  public deactivated (): void {
    this.websocketApi.disableInspection()
  }

  public handleEvents (message: Record<string, any>): void {
    console.log(message)
  }

  private getDevtoolsIFrame (): JQuery<HTMLElement> {
    return $('<iframe></iframe>')
      .attr('height', '80%')
      .attr('width', '100%')
      .attr('frameBorder', '0')
      .attr('scrolling', 'no')
      .attr('src', 'devtools/inspect_traffic.html')
  }
}
