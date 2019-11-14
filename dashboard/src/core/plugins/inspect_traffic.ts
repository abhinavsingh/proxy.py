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
    this.ensureIFrame()
  }

  public deactivated (): void {
    this.websocketApi.disableInspection()
  }

  public handleEvents (message: Record<string, any>): void {
    console.log(message)
  }

  private ensureIFrame (): void {
    if ($('#' + this.getDevtoolsIFrameID()).length === 0) {
      $('#' + this.name)
        .children('.app-body')
        .append(
          this.getDevtoolsIFrame()
        )
    }
  }

  private getDevtoolsIFrameID (): string {
    return this.name.concat('_inspector')
  }

  private getDevtoolsIFrame (): JQuery<HTMLElement> {
    return $('<iframe></iframe>')
      .attr('id', this.getDevtoolsIFrameID())
      .attr('height', '80%')
      .attr('width', '100%')
      .attr('padding', '0')
      .attr('margin', '0')
      .attr('frameBorder', '0')
      .attr('scrolling', 'no')
      .attr('src', 'devtools/inspect_traffic.html')
  }
}
