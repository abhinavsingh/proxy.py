/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

import {DashboardPlugin} from "../plugin";

export class HomePlugin extends DashboardPlugin {

  constructor (name: string) {
    super(name);
  }

  public initializeTab() : JQuery<HTMLElement> {
    return this.makeTab('Home', 'fa-home')
  }

  public initializeAppSkeleton(): JQuery<HTMLElement> {
    return $('<div></div>')
  }

  public activated(): void {}

  public deactivated(): void {}
}
