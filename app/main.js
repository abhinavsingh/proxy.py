const { app, BrowserWindow } = require('electron');
const http = require('http');

let win;

const httpGet = url => {
    return new Promise((resolve, reject) => {
        http.get(url, res => {
            res.setEncoding('utf8');
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => resolve(JSON.parse(body)));
        }).on('error', reject);
    });
};

async function createWindow () {
    // Create the browser window.
    win = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true
        }
    });

    win.webContents.openDevTools();

    let json = await httpGet('http://localhost:5858/json');
    let devtoolsFrontendUrlCompat = json[0]['devtoolsFrontendUrlCompat'];
    let webSocketDebuggerUrl = json[0]['webSocketDebuggerUrl'];
    win.loadURL(devtoolsFrontendUrlCompat);
    console.log(devtoolsFrontendUrlCompat);
    console.log(webSocketDebuggerUrl);

    // Emitted when the window is closed.
    win.on('closed', () => {
        win = null
    })
}

app.on('ready', createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', async () => {
    if (win === null) {
        await createWindow();
    }
});

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.
