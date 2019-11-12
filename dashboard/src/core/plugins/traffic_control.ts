/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

import {DashboardPlugin} from "../plugin";

export class TrafficControlPlugin extends DashboardPlugin {

  constructor (name: string) {
    super(name);
  }

  public getTab() : JQuery<HTMLElement> {
    return $('<a/>')
      .attr({
        href: '#',
        id: 'proxyControls'
      })
      .addClass('nav-link')
      .text('Traffic Controls')
      .prepend(
        $('<i/>')
          .addClass('fa')
          .addClass('fa-fw')
          .addClass('fa-lock')
      )
  }
}
