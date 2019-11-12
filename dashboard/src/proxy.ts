/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

import { WebsocketApi } from './core/ws'
import { IDashboardPlugin, IPluginConstructor } from './core/plugin'

import { HomePlugin } from './core/plugins/home'
import { InspectTrafficPlugin } from './core/plugins/inspect_traffic'
import { TrafficControlPlugin } from './core/plugins/traffic_control'
import { SettingsPlugin } from './core/plugins/settings'

import { MockRestApiPlugin } from './plugins/mock_rest_api'
import { ShortlinkPlugin } from './plugins/shortlink'

export class ProxyDashboard {
  private static plugins: Map<string, IDashboardPlugin> = new Map();

  private websocketApi: WebsocketApi

  constructor () {
    this.websocketApi = new WebsocketApi()

    const that = this
    $('#proxyTopNav>ul>li>a').on('click', function () {
      that.switchTab(this)
    })
  }

  public static addPlugin (name: string, Plugin: IPluginConstructor) {
    const p = new Plugin(name)
    $('#proxyTopNav ul').append(
      $('<li/>')
        .addClass('nav-item')
        .append(p.getTab())
    )
    ProxyDashboard.plugins.set(name, p)
  }

  private switchTab (element: HTMLElement) {
    const activeLi = $('#proxyTopNav>ul>li.active')
    const activeTabId = activeLi.children('a').attr('id')
    const clickedTabId = $(element).attr('id')
    const clickedTabContentId = $(element).text().trim().toLowerCase().replace(' ', '-')

    activeLi.removeClass('active')
    $(element.parentNode).addClass('active')
    console.log('Clicked id %s, showing %s', clickedTabId, clickedTabContentId)

    if (clickedTabId === activeTabId) {
      return
    }

    $('#app>div.proxy-data').hide()
    $('#' + clickedTabContentId).show()

    // TODO: Tab ids shouldn't be hardcoded.
    // Templatize proxy.html and refer to tab_id via enum or constants
    //
    // 1. Enable inspection if user moved to inspect tab
    // 2. Disable inspection if user moved away from inspect tab
    if (clickedTabId === 'proxyInspect') {
      this.websocketApi.enableInspection()
    } else if (activeTabId === 'proxyInspect') {
      this.websocketApi.disableInspection()
    }
  }
}

ProxyDashboard.addPlugin('home', HomePlugin)
ProxyDashboard.addPlugin('api_development', MockRestApiPlugin)
ProxyDashboard.addPlugin('inspect_traffic', InspectTrafficPlugin)
ProxyDashboard.addPlugin('shortlink', ShortlinkPlugin)
ProxyDashboard.addPlugin('traffic_control', TrafficControlPlugin)
ProxyDashboard.addPlugin('settings', SettingsPlugin);

(window as any).ProxyDashboard = ProxyDashboard
