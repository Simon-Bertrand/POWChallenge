/**
 * Webpack loader for .wasm files.
 * Inlines the binary as a raw base64 string to support universal decoding.
 */
module.exports = function (content) {
    // content is a Buffer when raw: true  
    const base64 = content.toString('base64');
    return `module.exports = ${JSON.stringify(base64)};`;
};
module.exports.raw = true; // receive input as Buffer, not string
