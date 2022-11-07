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

help:
	@echo "usage: make install"
	@echo "usage: make uninstall"
	@echo "usage: make debug"
	@echo "usage: make release"
	@echo "Static:"
	@echo "usage: make windows"
	@echo "usage: make linux_musl"