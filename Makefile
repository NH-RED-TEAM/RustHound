prog :=rusthound

cargo := $(shell command -v cargo 2> /dev/null)
cargo_v := $(shell cargo -V| cut -d ' ' -f 2)
rustup := $(shell command -v rustup 2> /dev/null)

check_cargo:
  ifndef cargo
    $(error cargo is not available, please install it! curl https://sh.rustup.rs -sSf | sh)
  else
	@echo "Make sure your cargo version is up to date! Current version is $(cargo_v)"
  endif

check_rustup:
  ifndef rustup
    $(error rustup is not available, please install it! curl https://sh.rustup.rs -sSf | sh)
  endif

release: check_cargo
	cargo build --release
	@echo "[+] You can find rusthound release version in target/release/ folder."

debug: check_cargo
	cargo build
	@echo "[+] You can find rusthound debug version in target/debug/ folder."

doc: check_cargo
	cargo doc --open --no-deps

install: check_cargo
	cargo install --path .
	@echo "[+] rusthound installed!"

uninstall:
	@cargo uninstall rusthound

install_windows_deps:
	@rustup install stable-x86_64-pc-windows-gnu --force-non-host
	@rustup target add x86_64-pc-windows-gnu

build_windows:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-gnu
	@echo "[+] You can find rusthound.exe in target/x86_64-pc-windows-gnu/release folder."

windows: check_rustup install_windows_deps build_windows

install_linux_musl_deps:
	#@rustup install x86_64-unknown-linux-musl --force-non-host
	@rustup target add x86_64-unknown-linux-musl

build_linux_musl:
	cargo build --release --target x86_64-unknown-linux-musl
	@echo "[+] You can find rusthound in target/x86_64-unknown-linux-musl/release folder."

linux_musl:	check_rustup install_linux_musl_deps build_linux_musl

install_macos_deps:
	@sudo git clone https://github.com/tpoechtrager/osxcross /usr/local/bin/osxcross || exit
	@sudo wget -P /usr/local/bin/osxcross/ -nc https://s3.dockerproject.org/darwin/v2/MacOSX10.10.sdk.tar.xz && sudo mv /usr/local/bin/osxcross/MacOSX10.10.sdk.tar.xz /usr/local/bin/osxcross/tarballs/
	@sudo UNATTENDED=yes OSX_VERSION_MIN=10.7 /usr/local/bin/osxcross/build.sh
	@sudo chmod 775 /usr/local/bin/osxcross/ -R
	@export PATH="/usr/local/bin/osxcross/target/bin:$PATH"
	@grep 'target.x86_64-apple-darwin' ~/.cargo/config || echo "[target.x86_64-apple-darwin]" >> ~/.cargo/config
	@grep 'linker = "x86_64-apple-darwin14-clang"' ~/.cargo/config || echo 'linker = "x86_64-apple-darwin14-clang"' >> ~/.cargo/config
	@grep 'ar = "x86_64-apple-darwin14-clang"' ~/.cargo/config || echo 'ar = "x86_64-apple-darwin14-clang"' >> ~/.cargo/config
	@echo "[?] Now you need to uncomment line 32 and comment line 34 in Cargo.toml for MacOS and run 'make macos'"

build_macos:
	@echo "[?] Make sure you have uncomment line 32 and comment line 34 in Cargo.toml for MacOS."
	@export PATH="/usr/local/bin/osxcross/target/bin:$PATH"
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-apple-darwin
	@echo "[+] You can find rusthound in target/x86_64-apple-darwin/release folder."

macos: build_macos

help:
	@echo ""
	@echo "Default:"
	@echo "usage: make install"
	@echo "usage: make uninstall"
	@echo "usage: make debug"
	@echo "usage: make release"
	@echo ""
	@echo "Static:"
	@echo "usage: make windows"
	@echo "usage: make linux_musl"
	@echo "usage: make macos"
	@echo ""
	@echo "Dependencies:"
	@echo "usage: make install_windows_deps"
	@echo "usage: make install_linux_musl_deps"
	@echo "usage: make install_macos_deps"
	@echo ""