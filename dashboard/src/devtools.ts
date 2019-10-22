/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
const path = require('path')
const fs = require('fs')
const ncp = require('ncp').ncp
ncp.limit = 16

const publicFolderPath = path.join(__dirname, 'public')
const destinationFolderPath = path.join(publicFolderPath, 'devtools')

const publicFolderExists = fs.existsSync(publicFolderPath)
if (!publicFolderExists) {
  console.error(publicFolderPath + ' folder doesn\'t exist, make sure you are in the right directory.')
  process.exit(1)
}

const destinationFolderExists = fs.existsSync(destinationFolderPath)
if (!destinationFolderExists) {
  console.error(destinationFolderPath + ' folder doesn\'t exist, make sure you are in the right directory.')
  process.exit(1)
}

const chromeDevTools = path.dirname(require.resolve('chrome-devtools-frontend/front_end/inspector.html'))

console.log(chromeDevTools + ' ---> ' + destinationFolderPath)
ncp(chromeDevTools, destinationFolderPath, (err: any) => {
  if (err) {
    return console.error(err)
  }
  console.log('Copy successful!!!')
})
