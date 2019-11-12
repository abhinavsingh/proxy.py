/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

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
