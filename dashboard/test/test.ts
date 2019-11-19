/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
/* global describe, it, expect */

import { ProxyDashboard } from '../src/proxy'

describe('test suite', () => {
  it('initializes', () => {
    expect(new ProxyDashboard()).toBeTruthy()
  })
})
