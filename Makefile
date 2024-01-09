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

update_rustup:
	rustup update

release: check_cargo
	cargo build --release
	cp target/release/$(prog) .
	@echo -e "[+] You can find \033[1;32m$(prog)\033[0m in your current folder."

debug: check_cargo
	cargo build
	cp target/debug/$(prog) ./$(prog)_debug
	@echo -e "[+] You can find \033[1;32m$(prog)_debug\033[0m in your current folder."

doc: check_cargo
	cargo doc --open --no-deps

install: check_cargo
	cargo install --path .
	@echo "[+] rusthound installed!"

uninstall:
	@cargo uninstall rusthound

clean:
	rm target -rf

install_windows_deps: update_rustup
	@rustup install stable-x86_64-pc-windows-gnu --force-non-host
	@rustup target add x86_64-pc-windows-gnu
	@rustup install stable-i686-pc-windows-gnu --force-non-host
	@rustup target add i686-pc-windows-gnu

build_windows_x64:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/$(prog).exe .
	@echo -e "[+] You can find \033[1;32m$(prog).exe\033[0m in your current folder."

build_windows_x86:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target i686-pc-windows-gnu
	cp target/i686-pc-windows-gnu/release/$(prog).exe ./$(prog)_x86.exe
	@echo -e "[+] You can find \033[1;32m$(prog)_x86.exe\033[0m in your current folder."

windows: check_rustup install_windows_deps build_windows_x64

windows_x64: check_rustup install_windows_deps build_windows_x64

windows_x86: check_rustup install_windows_deps build_windows_x86

build_windows_noargs:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-gnu --features noargs
	cp target/x86_64-pc-windows-gnu/release/$(prog).exe ./$(prog)_noargs.exe
	@echo -e "[+] You can find \033[1;32m$(prog)_noargs.exe\033[0m in your current folder."

windows_noargs: check_rustup install_windows_deps build_windows_noargs

install_linux_musl_deps:
	@rustup install x86_64-unknown-linux-musl --force-non-host
	@rustup target add x86_64-unknown-linux-musl

build_linux_musl:
	cross build --target x86_64-unknown-linux-musl --release --features nogssapi --no-default-features
	cp target/x86_64-unknown-linux-musl/release/$(prog) ./$(prog)_musl
	@echo -e "[+] You can find \033[1;32m$(prog)_musl\033[0m in your current folder."

linux_musl: check_rustup install_cross build_linux_musl

install_linux_deps:update_rustup
	@rustup install stable-x86_64-unknown-linux-gnu --force-non-host
	@rustup target add x86_64-unknown-linux-gnu

build_linux_aarch64:
	cross build --target aarch64-unknown-linux-gnu --release --features nogssapi --no-default-features
	cp target/aarch64-unknown-linux-gnu/release/$(prog) ./$(prog)_aarch64
	@echo -e "[+] You can find \033[1;32m$(prog)_aarch64\033[0m in your current folder."

linux_aarch64: check_rustup install_cross build_linux_aarch64

build_linux_x86_64:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --features nogssapi --target x86_64-unknown-linux-gnu --no-default-features
	cp target/x86_64-unknown-linux-gnu/release/$(prog) ./$(prog)_x86_64
	@echo -e "[+] You can find \033[1;32m$(prog)_x86_64\033[0m in your current folder."

linux_x86_64: check_rustup install_linux_deps build_linux_x86_64

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
	@export PATH="/usr/local/bin/osxcross/target/bin:$PATH"
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-apple-darwin --features nogssapi --no-default-features
	cp target/x86_64-apple-darwin/release/$(prog).exe ./$(prog)_MacOS
	@echo -e "[+] You can find \033[1;32m$(prog)_MacOS\033[0m in your current folder."

macos: build_macos

install_cross:
	@cargo install --version 0.1.16 cross

arm_musl: check_rustup install_cross
	cross build --target arm-unknown-linux-musleabi --release --features nogssapi --no-default-features
	cp target/arm-unknown-linux-musleabi/release/$(prog) ./$(prog)_arm_musl
	@echo -e "[+] You can find \033[1;32m$(prog)_arm_musl\033[0m in your current folder."

armv7: check_rustup install_cross
	cross build --target armv7-unknown-linux-gnueabihf --release --features nogssapi --no-default-features
	cp target/armv7-unknown-linux-gnueabihf/release/$(prog) ./$(prog)_armv7
	@echo -e "[+] You can find \033[1;32m$(prog)_armv7\033[0m in your current folder."

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
	@echo "usage: make windows_x64"
	@echo "usage: make windows_x86"
	@echo "usage: make linux_aarch64"
	@echo "usage: make linux_x86_64"
	@echo "usage: make linux_musl"
	@echo "usage: make macos"
	@echo "usage: make arm_musl"
	@echo "usage: make armv7"
	@echo ""
	@echo "Without cli argument:"
	@echo "usage: make windows_noargs"
	@echo ""
	@echo "Dependencies:"
	@echo "usage: make install_windows_deps"
	@echo "usage: make install_linux_musl_deps"
	@echo "usage: make install_macos_deps"
	@echo ""