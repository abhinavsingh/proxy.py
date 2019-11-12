/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
import { DashboardPlugin } from '../core/plugin'

export class ShortlinkPlugin extends DashboardPlugin {
  public name: string = 'shortlink'
  public title: string = 'Short Links'

  public initializeTab () : JQuery<HTMLElement> {
    return this.makeTab(this.title, 'fa-bolt')
  }

  public initializeHeader (): JQuery<HTMLElement> {
    return this.makeHeader(this.title)
  }

  public initializeBody (): JQuery<HTMLElement> {
    return $('<div></div>')
  }

  public activated (): void {}

  public deactivated (): void {}
}
