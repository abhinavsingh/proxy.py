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
  private readonly websocketApi: WebsocketApi

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
        $('<section></section>')
          .attr('id', p.name)
          .addClass('proxy-dashboard-plugin')
          .append(
            $('<div></div>')
              .addClass('app-header')
              .append(p.initializeHeader())
          )
          .append(
            $('<div></div>')
              .addClass('app-body')
              .append(p.initializeBody())
          )
      )
      this.plugins.set(p.name, p)
    }

    const that = this
    $('#proxyTopNav>ul>li>a').on('click', function () {
      that.switchTab(this)
    })
    window.onhashchange = function () {
      that.onHashChange()
    }
  }

  public static addPlugin (Plugin: IPluginConstructor) {
    ProxyDashboard.plugins.push(Plugin)
  }

  private onHashChange () {
    const activeLi = $('#proxyTopNav>ul>li.active')
    const activeTabPluginName = activeLi.children('a').attr('plugin_name')
    const activeTabHash = activeLi.children('a').attr('href')
    if (window.location.hash !== activeTabHash) {
      this.navigate(activeTabPluginName, window.location.hash.substring(1))
    }
  }

  private switchTab (element: HTMLElement) {
    const activeTabPluginName = $('#proxyTopNav>ul>li.active').children('a').attr('plugin_name')
    const clickedTabPluginName = $(element).attr('plugin_name')
    if (clickedTabPluginName === activeTabPluginName) {
      return
    }

    this.navigate(activeTabPluginName, clickedTabPluginName)
    window.history.pushState(null, null, '/dashboard/#' + clickedTabPluginName)
  }

  private navigate (activeTabPluginName: string, clickedTabPluginName: string) {
    console.log('Navigating from', activeTabPluginName, 'to', clickedTabPluginName)
    if (activeTabPluginName !== undefined) {
      $('#' + this.plugins.get(activeTabPluginName).tabId()).parent('li').removeClass('active')
    }
    $('#' + this.plugins.get(clickedTabPluginName).tabId()).parent('li').addClass('active')

    $('#proxyDashboard>.proxy-dashboard-plugin').hide()
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
ProxyDashboard.addPlugin(SettingsPlugin)

const dashboard = new ProxyDashboard()
console.log(dashboard)
