import typescript from 'rollup-plugin-typescript';
import copy from 'rollup-plugin-copy';
import obfuscatorPlugin from 'rollup-plugin-javascript-obfuscator';

export const input = 'src/proxy.ts';
export const output = {
    file: 'public/dashboard/proxy.js',
    format: 'umd',
    name: 'proxy',
    sourcemap: true
};
export const plugins = [
    typescript(),
    copy({
        targets: [{
            src: 'static/**/*',
            dest: 'public/dashboard',
        }, {
            src: 'src/proxy.html',
            dest: 'public/dashboard',
        }, {
            src: 'src/proxy.css',
            dest: 'public/dashboard',
        }, {
            src: 'src/manifest.json',
            dest: 'public/dashboard',
        }, {
            src: 'src/core/plugins/inspect_traffic.json',
            dest: 'public/dashboard/devtools'
        }, {
            src: 'src/core/plugins/inspect_traffic.js',
            dest: 'public/dashboard/devtools'
        }, {
            src: 'src/core/plugins/inspect_traffic.html',
            dest: 'public/dashboard/devtools'
        }],
    }),
    obfuscatorPlugin({
        log: false,
        sourceMap: true,
        compact: true,
        stringArray: true,
        rotateStringArray: true,
        transformObjectKeys: true,
        stringArrayThreshold: 1,
        stringArrayEncoding: 'rc4',
        identifierNamesGenerator: 'mangled',
    })
];
