const typescript = require('rollup-plugin-typescript');
const copy = require('rollup-plugin-copy');
const obfuscatorPlugin = require('rollup-plugin-javascript-obfuscator');

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
                src: 'static/**/*',
                dest: '../public',
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
    ]
};
