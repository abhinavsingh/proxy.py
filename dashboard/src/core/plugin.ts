/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

export class DashboardPlugin {
  private readonly name: string;

  constructor (name: string) {
    this.name = name
  }

  public getTab() : JQuery<HTMLElement> {
    return $('')
  }
}
