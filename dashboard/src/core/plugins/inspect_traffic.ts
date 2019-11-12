/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
import { DashboardPlugin } from '../plugin'

export class InspectTrafficPlugin extends DashboardPlugin {
  public name: string = 'inspect_traffic'

  public initializeTab () : JQuery<HTMLElement> {
    return this.makeTab('Inspect Traffic', 'fa-binoculars')
  }

  public initializeHeader (): JQuery<HTMLElement> {
    return $('<div></div>')
      .addClass('container-fluid')
      .append(
        $('<div></div>')
          .addClass('row')
          .append(
            $('<div></div>')
              .addClass('col-6')
              .append(
                $('<p></p>')
                  .addClass('h3')
                  .text('Inspect Traffic')
              )
          )
      )
  }

  public initializeBody (): JQuery<HTMLElement> {
    return $('<div></div>')
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
}
