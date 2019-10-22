let jsdom = require('jsdom');
let WebSocket = require('ws')

const window = new jsdom.JSDOM('<!DOCTYPE html><head><title></title></head><body></body></html>').window;

global.jQuery = global.$ = require('jquery')(window);
global.window = window;
global.document = window.document;
global.WebSocket = WebSocket;
