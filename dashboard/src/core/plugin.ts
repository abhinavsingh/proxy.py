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
  initializeTab(): JQuery<HTMLElement>
  initializeAppSkeleton(): JQuery<HTMLElement>
  activated(): void
  deactivated(): void
}

export interface IPluginConstructor {
  new (name: string): IDashboardPlugin
}

export abstract class DashboardPlugin implements IDashboardPlugin {
  public readonly name: string

  protected constructor (name: string) {
    this.name = name
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
  public abstract initializeAppSkeleton(): JQuery<HTMLElement>
  public abstract activated(): void
  public abstract deactivated(): void
}
