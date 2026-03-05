const fs = require('fs');
const path = require('path');

const newVersion = process.argv[2];
if (!newVersion) {
    console.error("Usage: node scripts/bump_version.js <new-version>");
    process.exit(1);
}

// 1. Update client-js
const clientPkg = path.join(__dirname, '..', 'client-js', 'package.json');
if (fs.existsSync(clientPkg)) {
    let data = JSON.parse(fs.readFileSync(clientPkg, 'utf8'));
    data.version = newVersion;
    fs.writeFileSync(clientPkg, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated client-js to ${newVersion}`);
}

// 2. Update servers/js
const jsServerPkg = path.join(__dirname, '..', 'servers', 'js', 'package.json');
if (fs.existsSync(jsServerPkg)) {
    let data = JSON.parse(fs.readFileSync(jsServerPkg, 'utf8'));
    data.version = newVersion;
    fs.writeFileSync(jsServerPkg, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated servers/js to ${newVersion}`);
}

// 3. Update servers/rust
const rustCargo = path.join(__dirname, '..', 'servers', 'rust', 'Cargo.toml');
if (fs.existsSync(rustCargo)) {
    let cargoData = fs.readFileSync(rustCargo, 'utf8');
    cargoData = cargoData.replace(/^version\s*=\s*".*"/m, `version = "${newVersion}"`);
    fs.writeFileSync(rustCargo, cargoData);
    console.log(`Updated servers/rust to ${newVersion}`);
}

// 4. Update servers/python
const pyProject = path.join(__dirname, '..', 'servers', 'python', 'pyproject.toml');
if (fs.existsSync(pyProject)) {
    let pyData = fs.readFileSync(pyProject, 'utf8');
    pyData = pyData.replace(/^version\s*=\s*".*"/m, `version = "${newVersion}"`);
    fs.writeFileSync(pyProject, pyData);
    console.log(`Updated servers/python to ${newVersion}`);
}

console.log("Versioning complete!");
