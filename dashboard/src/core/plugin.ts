/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
import { WebsocketApi } from "./ws"

export interface IDashboardPlugin {
  name: string
  initializeTab(): JQuery<HTMLElement>
  initializeSkeleton(): JQuery<HTMLElement>
  activated(): void
  deactivated(): void
}

export interface IPluginConstructor {
  new (websocketApi: WebsocketApi): IDashboardPlugin
}

export abstract class DashboardPlugin implements IDashboardPlugin {
  public abstract readonly name: string
  protected websocketApi: WebsocketApi

  protected constructor (websocketApi: WebsocketApi) {
    this.websocketApi = websocketApi
  }

  public makeTab(name: string, icon: string) : JQuery<HTMLElement> {
    return $('<a/>')
      .attr({
        href: '#',
        plugin_name: this.name
      })
      .addClass('nav-link')
      .text(name)
      .prepend(
        $('<i/>')
          .addClass('fa')
          .addClass('fa-fw')
          .addClass(icon)
      )
  }

  public abstract initializeTab() : JQuery<HTMLElement>
  public abstract initializeSkeleton(): JQuery<HTMLElement>
  public abstract activated(): void
  public abstract deactivated(): void
}
