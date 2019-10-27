/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
import {WebsocketApi} from "./inspect"
import {ApiDevelopment} from "./api"

export class ProxyDashboard {
  private websocketApi: WebsocketApi
  private apiDevelopment: ApiDevelopment

  constructor () {
    this.websocketApi = new WebsocketApi()
    const that = this
    $('#proxyTopNav>ul>li>a').on('click', function () {
      that.switchTab(this)
    })
    this.apiDevelopment = new ApiDevelopment()
  }

  public static getTime () {
    const date = new Date()
    return date.getTime()
  }

  public static setServerStatusDanger () {
    $('#proxyServerStatus').parent('div')
      .removeClass('text-success')
      .addClass('text-danger')
  }

  public static setServerStatusSuccess (summary: string) {
    $('#proxyServerStatus').parent('div')
      .removeClass('text-danger')
      .addClass('text-success')
    $('#proxyServerStatusSummary').text(
      '(' + summary + ')')
  }

  private switchTab (element: HTMLElement) {
    const activeLi = $('#proxyTopNav>ul>li.active')
    const activeTabId = activeLi.children('a').attr('id')
    const clickedTabId = $(element).attr('id')

    activeLi.removeClass('active')
    $(element.parentNode).addClass('active')
    console.log('%s clicked, id %s', $(element).text().trim(), clickedTabId)

    // TODO: Tab ids shouldn't be hardcoded.
    // Templatize proxy.html and refer to tab_id via enum or constants
    //
    // 1. Enable inspection if user moved to inspect tab
    // 2. Disable inspection if user moved away from inspect tab
    // 3. Do nothing if activeTabId == clickedTabId
    if (clickedTabId !== activeTabId) {
      if (clickedTabId === 'proxyInspect') {
        this.websocketApi.enableInspection()
      } else if (activeTabId === 'proxyInspect') {
        this.websocketApi.disableInspection()
      }
    }
  }
}

(window as any).ProxyDashboard = ProxyDashboard
