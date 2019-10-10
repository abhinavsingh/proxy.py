const path = require('path');
const fs = require('fs');
const ncp = require('ncp').ncp;
ncp.limit = 16;

const publicFolderPath = path.join(__dirname, 'public');
const destinationFolderPath = path.join(publicFolderPath, 'devtools');

const publicFolderExists = fs.existsSync(publicFolderPath);
if (!publicFolderExists) {
    console.error(publicFolderPath + ' folder doesn\'t exist, make sure you are in the right directory.');
    process.exit(1);
}

const destinationFolderExists = fs.existsSync(destinationFolderPath);
if (!destinationFolderExists) {
    console.error(destinationFolderPath + ' folder doesn\'t exist, make sure you are in the right directory.');
    process.exit(1);
}

const chromeDevTools = path.dirname(require.resolve('chrome-devtools-frontend/front_end/inspector.html'));

console.log('Copying recursively...');
console.log(chromeDevTools + ' ---> ' + destinationFolderPath);
ncp(chromeDevTools, destinationFolderPath, (err) => {
    if (err) {
        return console.error(err);
    }
    console.log('Copy successful!!!');
});
