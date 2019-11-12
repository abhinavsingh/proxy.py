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
import { SettingsPlugin } from './core/plugins/settings'

import { MockRestApiPlugin } from './plugins/mock_rest_api'
import { ShortlinkPlugin } from './plugins/shortlink'
import { TrafficControlPlugin } from './plugins/traffic_control'

export class ProxyDashboard {
  private static plugins: IPluginConstructor[] = [];
  private plugins: Map<string, IDashboardPlugin> = new Map();

  private websocketApi: WebsocketApi

  constructor () {
    this.websocketApi = new WebsocketApi()

    for (const Plugin of ProxyDashboard.plugins) {
      const p = new Plugin(this.websocketApi)
      $('#proxyTopNav ul').append(
        $('<li/>')
          .addClass('nav-item')
          .append(p.initializeTab())
      )
      $('#proxyDashboard').append(
        $('<div></div>')
          .attr('id', p.name)
          .addClass('proxy-data')
          .append(p.initializeSkeleton())
      )
      this.plugins.set(p.name, p)
    }

    const that = this
    $('#proxyTopNav>ul>li>a').on('click', function () {
      that.switchTab(this)
    })
  }

  public static addPlugin (Plugin: IPluginConstructor) {
    ProxyDashboard.plugins.push(Plugin)
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
      this.plugins.get(activeTabPluginName).deactivated()
    }
    this.plugins.get(clickedTabPluginName).activated()
  }
}

ProxyDashboard.addPlugin(HomePlugin)
ProxyDashboard.addPlugin(MockRestApiPlugin)
ProxyDashboard.addPlugin(InspectTrafficPlugin)
ProxyDashboard.addPlugin(ShortlinkPlugin)
ProxyDashboard.addPlugin(TrafficControlPlugin)
ProxyDashboard.addPlugin(SettingsPlugin);

(window as any).ProxyDashboard = ProxyDashboard
