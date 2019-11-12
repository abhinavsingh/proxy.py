/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

import { WebsocketApi } from './core/ws'
import { DashboardPlugin } from './core/plugin'

import { MockRestApiPlugin } from './plugins/mock_rest_api'

export class ProxyDashboard {
  private static plugins: Map<string, DashboardPlugin> = new Map();

  private websocketApi: WebsocketApi

  constructor () {
    this.websocketApi = new WebsocketApi()

    const that = this
    $('#proxyTopNav>ul>li>a').on('click', function () {
      that.switchTab(this)
    })
  }

  public static addPlugin (name: string, Plugin: typeof DashboardPlugin) {
    ProxyDashboard.plugins.set(name, new Plugin(name))
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

ProxyDashboard.addPlugin('mock_rest_api', MockRestApiPlugin);
(window as any).ProxyDashboard = ProxyDashboard
