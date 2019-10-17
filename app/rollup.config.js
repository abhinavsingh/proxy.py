const typescript = require('rollup-plugin-typescript');
const copy = require('rollup-plugin-copy');
const obfuscatorPlugin = require('rollup-plugin-javascript-obfuscator');
import { uglify } from 'rollup-plugin-uglify';

module.exports = {
    input: 'src/proxy.ts',
    output: {
        file: '../public/proxy.js',
        format: 'umd',
        name: 'projectbundle',
        sourcemap: true
    },
    plugins: [
        typescript(),
        copy({
            targets: [{
                src: 'src/index.html',
                dest: '../public',
            }],
        }),
        uglify(),
        obfuscatorPlugin({
            compact: true,
        })
    ]
};
