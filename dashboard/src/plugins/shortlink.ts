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
  public name: string = 'shortlink';

  public initializeTab () : JQuery<HTMLElement> {
    return this.makeTab('Short Links', 'fa-bolt')
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
                  .text('Shortlink')
              )
          )
      )
  }

  public initializeBody (): JQuery<HTMLElement> {
    return $('<div></div>')
  }

  public activated (): void {}

  public deactivated (): void {}
}
