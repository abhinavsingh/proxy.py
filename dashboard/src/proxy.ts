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
        .append(p.initializeTab())
    )
    $('#proxyDashboard').append(
      $('<div></div>')
        .attr('id', p.name)
        .addClass('proxy-data')
        .append(p.initializeAppSkeleton())
    )
    ProxyDashboard.plugins.set(name, p)
  }

  private switchTab (element: HTMLElement) {
    const activeLi = $('#proxyTopNav>ul>li.active')
    const activeTabPluginName = activeLi.children('a').attr('plugin_name')
    const clickedTabPluginName = $(element).attr('plugin_name')

    activeLi.removeClass('active')
    $(element.parentNode).addClass('active')
    console.log('Showing plugin content', clickedTabPluginName)

    if (clickedTabPluginName === activeTabPluginName) {
      return
    }

    $('#proxyDashboard>div.proxy-data').hide()
    $('#' + clickedTabPluginName).show()

    if (activeTabPluginName !== undefined) {
      ProxyDashboard.plugins.get(activeTabPluginName).deactivated()
    }
    ProxyDashboard.plugins.get(clickedTabPluginName).activated()
  }
}

ProxyDashboard.addPlugin('home', HomePlugin)
ProxyDashboard.addPlugin('api_development', MockRestApiPlugin)
ProxyDashboard.addPlugin('inspect_traffic', InspectTrafficPlugin)
ProxyDashboard.addPlugin('shortlink', ShortlinkPlugin)
ProxyDashboard.addPlugin('traffic_control', TrafficControlPlugin)
ProxyDashboard.addPlugin('settings', SettingsPlugin);

(window as any).ProxyDashboard = ProxyDashboard
