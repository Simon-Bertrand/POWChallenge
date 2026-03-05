const path = require('path');

module.exports = {
    entry: './src/index.ts',
    target: 'web',
    mode: 'production',
    output: {
        filename: 'bundle.min.js',
        path: path.resolve(__dirname, 'dist'),
        iife: true,
        globalObject: 'this',
    },
    resolve: {
        extensions: ['.ts', '.js'],
        fallback: {
            fs: false,
            path: false,
            crypto: false,
        },
    },
    module: {
        rules: [
            {
                test: /\.ts$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
            {
                // Emits WASM as base64 to support decoding via Buffer (Node) or atob (Browser).
                test: /\.wasm$/,
                use: path.resolve(__dirname, 'wasm-loader.js'),
                type: 'javascript/auto',
            },
        ],
    },
    devtool: false,
};
