.PHONY: all clean build-client build-js-server build-rust-server build-py-server test bump-version publish

all: clean build-client build-js-server build-rust-server build-py-server

clean:
	@echo "Cleaning build directory..."
	rm -rf build
	rm -rf client-js/dist
	rm -rf servers/js/dist
	cd servers/rust && cargo clean
	rm -rf servers/python/dist
	mkdir -p build

build-client:
	@echo "Building Client JS..."
	cd client-js && npm install && npm run build
	mkdir -p build/js-client
	cp -r client-js/dist/* build/js-client/

build-js-server:
	@echo "Building JS Server..."
	cd servers/js && npm install && npm run build
	mkdir -p build/js-server
	cp -r servers/js/dist/* build/js-server/
	cp servers/js/package.json build/js-server/ || true

build-rust-server:
	@echo "Building Rust Server Libs..."
	cd servers/rust && cargo clean && cargo build --release
	mkdir -p build/rust-server
	cp servers/rust/Cargo.toml build/rust-server/
	# Copy the compiled libraries for distribution
	find servers/rust/target/release -maxdepth 1 -type f \( -name "*.dll" -o -name "*.so" -o -name "*.dylib" -o -name "*.lib" -o -name "*.a" -o -name "*.rlib" \) -exec cp {} build/rust-server/ \; 2>/dev/null || true

build-py-server:
	@echo "Building Python Server (wheel)..."
	cd servers/python && python -m pip install --quiet build && python -m build
	mkdir -p build/py-server
	cp -r servers/python/dist/*.whl build/py-server/

# Ensure client-js is built, servers/js is compiled, and servers/js deps are installed
# before running e2e tests. tests/e2e.js requires argon2 from servers/js/node_modules
# and the Express example requires servers/js/dist/index.js (gitignored, must be built).
test: build-client
	@echo "Building and installing JS server library..."
	cd servers/js && npm install && npm run build
	@echo "Running Unified E2E Tests..."
	node tests/e2e.js

bump-version:
	@if [ -z "$(V)" ]; then echo "Usage: make bump-version V=1.0.1"; exit 1; fi
	node scripts/bump_version.js $(V)

publish:
	@echo "Deploying packages to npm, PyPI, and crates.io..."
	@echo "----------------------------------------"
	@echo "Publishing client-js to npm..."
	cd client-js && npm i && npm run build && npm publish --access public
	@echo "----------------------------------------"
	@echo "Publishing servers/js to npm..."
	cd servers/js && npm i && npm run build && npm publish --access public
	@echo "----------------------------------------"
	@echo "Publishing servers/python to PyPI..."
	cd servers/python && rm -rf dist/ build/ *.egg-info && python -m build && python -m twine upload dist/*
	@echo "----------------------------------------"
	@echo "Publishing servers/rust to crates.io..."
	cd servers/rust && cargo publish
	@echo "----------------------------------------"
	@echo "[SUCCESS] All packages successfully deployed!"
