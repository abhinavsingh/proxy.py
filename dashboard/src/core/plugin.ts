/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

export interface IDashboardPlugin {
  name: string
  getTab(): JQuery<HTMLElement>
}

export interface IPluginConstructor {
  new (name: string): IDashboardPlugin
}

export abstract class DashboardPlugin implements IDashboardPlugin {
  public readonly name: string

  protected constructor (name: string) {
    this.name = name
  }

  public abstract getTab() : JQuery<HTMLElement>
}
