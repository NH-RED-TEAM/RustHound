# RustHound

<p align="center">
  <a href="https://crates.io/crates/rusthound"><img alt="Crates.io" src="https://img.shields.io/crates/v/rusthound?style=for-the-badge"></a>
  <img alt="GitHub" src="https://img.shields.io/github/license/OPENCYBER-FR/RustHound?style=for-the-badge">
  <img alt="Linux supported" src="https://img.shields.io/badge/Supported%20OS-Linux-orange?style=for-the-badge">
  <img alt="Windows supported" src="https://img.shields.io/badge/Supported%20OS-Windows-green?style=for-the-badge">
  <!--<img alt="MacOS supported" src="https://img.shields.io/badge/Supported%20OS-MacOS-blue?style=for-the-badge">-->
  <a href="https://twitter.com/intent/follow?screen_name=OPENCYBER_FR" title="Follow"><img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/OPENCYBER_FR?label=OPENCYBER_FR&style=for-the-badge"></a>
  <a href="https://twitter.com/intent/follow?screen_name=g0h4n_0" title="Follow"><img src="https://img.shields.io/twitter/follow/g0h4n_0?label=g0h4n&style=for-the-badge"></a>
  <br>
</p>

<p align="center">
<img width="30%" src="img/rusthound_logo_v3.png">
</p>

# Summary

- [Limitation](#limitations)
- [Description](#description)
- [Usage](#usage)
- [Demo](#demo)
- [How to compile it?](#how-to-compile-it)
  - [Using Makefile](#using-makefile)
  - [Using Dockerfile](#using-dockerfile)
  - [Using Cargo](#using-cargo)
  - [Linux x86_64 static version](#manually-for-linux-x86_64-static-version)
  - [Windows static version from Linux](#manually-for-windows-static-version-from-linux)
- [How to build documentation?](#how-to-build-documentation)
- [Roadmap](#-roadmap)
- [Links](#link-links)

# Limitations

Not all SharpHound features are implemented yet but some are existing in RustHound and do not in SharpHound or BloodHound-Python. Please refer to the [roadmap](#-roadmap) for more information.

# Description

RustHound is a **cross-platform** BloodHound collector tool, written in Rust. (Linux,Windows,MacOS)

No anti-virus detection and **cross-compiled**.

RustHound generate users,groups,computers,ous,gpos,containers,domains json files to analyze it with BloodHound application.

> 💡 If you can use SharpHound.exe, use it.
> Rusthound is a backup solution if SharpHound.exe is detected by AV or if SharpHound.exe isn't executable from the system where you have access to.

# Usage

```bash
USAGE:
    rusthound [FLAGS] [OPTIONS] --domain <domain>

FLAGS:
        --dns-tcp          Use TCP instead of UDP for DNS queries
        --fqdn-resolver    [MODULE] Use fqdn-resolver module to get computers IP address
    -h, --help             Prints help information
        --ldaps            Prepare ldaps request. Like ldaps://G0H4N.LAB/
    -v                     Sets the level of verbosity
    -V, --version          Prints version information
    -z, --zip              RustHound will compress the JSON files into a zip archive (doesn't work with Windows)

OPTIONS:
    -d, --domain <domain>                Domain name like: G0H4N.LAB
    -f, --ldapfqdn <ldapfqdn>            Domain Controler FQDN like: DC01.G0H4N.LAB
    -i, --ldapip <ldapip>                Domain Controller IP address
    -p, --ldappassword <ldappassword>    Ldap password to use
    -P, --ldapport <ldapport>            Ldap port, default is 389
    -u, --ldapusername <ldapusername>    Ldap username to use
    -n, --name-server <name-server>      Alternative IP address name server to use for queries
    -o, --dirpath <path>                 Path where you would like to save json files
```

# How to compile it?

## Using Makefile

You can use **make** command to install Rusthound or to compile it for Linux or Windows.

```bash
make install
rusthount -h
```

More command in the **Makefile**:

```bash
make help
  usage: make install
  usage: make uninstall
  usage: make debug
  usage: make release
  usage: make windows
```

## Using Dockerfile

Use RustHound with docker to make sure to have all dependencies.

```bash
docker build -t rusthound .
docker run rusthound -h
```

## Using Cargo

You need to install rust on your system (Windows/Linux/MacOS).

[https://www.rust-lang.org/fr/tools/install](https://www.rust-lang.org/fr/tools/install)

RustHound support Kerberos/GSSAPI but this means that it needs Clang and its development libraries, as well as the Kerberos development libraries. On Debian/Ubuntu, that means **clang-N**, **libclang-N-dev** and **libkrb5-dev**.

For example:
```bash
#Debian/Ubuntu
apt-get -y install gcc libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit
```

Here is how to compile the "release" and "debug" versions from "cargo" command.

```bash
git clone https://github.com/OPENCYBER-FR/RustHound
cd RustHound
cargo build --release
#or debug version
cargo b
```

The result can be found in "target/release" or in "target/debug" folder.

Below you can find the compilation methodology for each of the OS from Linux.
If you need another compilation system, please consult the list in this link : [https://doc.rust-lang.org/nightly/rustc/platform-support.html](https://doc.rust-lang.org/nightly/rustc/platform-support.html)


## Manually for Linux x86_64 static version
```bash
#Install rustup and cargo in Linux
curl https://sh.rustup.rs -sSf | sh

#Add Linux deps
rustup install stable-x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu

#Static compilation for Linux
git clone https://github.com/OPENCYBER-FR/RustHound
cd RustHound
CFLAGS="-lrt";LDFLAGS="-lrt";RUSTFLAGS='-C target-feature=+crt-static';cargo build --release --target x86_64-unknown-linux-gnu
```

The result can be found in "target/x86_64-unknown-linux-gnu/release" folder.


## Manually for Windows static version from Linux
```bash
#Install rustup and cargo in Linux
curl https://sh.rustup.rs -sSf | sh

#Add Windows deps
rustup install stable-x86_64-pc-windows-gnu
rustup target add x86_64-pc-windows-gnu

#Static compilation for Windows
git clone https://github.com/OPENCYBER-FR/RustHound
cd RustHound
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-gnu
```

The result can be found in "target/x86_64-pc-windows-gnu/release" folder.

# How to build the documentation?

```bash
git clone https://github.com/OPENCYBER-FR/RustHound
cd RustHound
cargo doc --open --no-deps
```

# Demo

Examples are done on the [GOADv2](https://github.com/Orange-Cyberdefense/GOAD) implemented by [mayfly](https://twitter.com/M4yFly):

```bash
# Linux with username:password
./rusthound -d north.sevenkingdoms.local -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo/rusthound_north -z

# Linux with username:password and ldaps
./rusthound -d north.sevenkingdoms.local --ldaps -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo/rusthound_north -z 
# Linux with username:password and ldaps and custom port
./rusthound -d north.sevenkingdoms.local --ldaps -P 3636 -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo/rusthound_north -z 

# Linux with username:password and ldaps and fqdn resolver module
./rusthound -d north.sevenkingdoms.local --ldaps -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo/rusthound_north --fqdn-resolver 
# Linux with username:password and ldaps and fqdn resolver module and tcp dns request and custom name server
./rusthound -d north.sevenkingdoms.local --ldaps -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo/rusthound_north --fqdn-resolver --tcp-dns --name-server 192.168.56.10 -z

# Tips to redirect and append both standard output and standard error to a file > /tmp/rh_output 2>&1
./rusthound -d north.sevenkingdoms.local --ldaps -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo/rusthound_north --fqdn-resolver > /tmp/rh_output 2>&1


# Windows with GSSAPI session
rusthound.exe -d sevenkingdoms.local --ldapfqdn kingslanding
```
<p align="center">
<img width="100%" src="img/demo.gif">
</p>

You can find the custom queries used in the demo, in the resource folder.

Use the following command to install it:

```bash
cp resources/customqueries.json ~/.config/bloodhound/customqueries.json
```

#  🚥 Roadmap

## Authentification
  - [x] ldap (389)
  - [x] ldaps (636)
  - [x] `BIND`
  - [ ] `NTLM`
  - [x] `GSSAPI` for Windows ok but not tested for Linux

## Outputs
  - [x] users.json
  - [x] groups.json
  - [x] computers.json
  - [x] ous.json
  - [x] gpos.json
  - [x] containers.json
  - [x] domains.json
  - [x] args and function to zip json files **--zip**

## Modules

- [x] Retreive LAPS password if your user can read them **automatic**
- [x] Resolve FQDN computers found to IP address **--fqdn-resolver**
- [ ] Retrieve certificates for ESC exploitation with [Certipy](https://github.com/ly4k/Certipy) **--enum-certificates**
- [ ] Kerberos attack module (ASREPROASTING,KERBEROASTING) **--attack-kerberos**
- [ ] Retrieve datas from trusted domains  **--follow-trust** (Currently working on it, got beta version of this module)


## Bloodhound v4.2

- Parsing Features
  - [x] `AllowedToDelegate`
  - [x] `AllowedToAct`
  - [x] `Properties:sidhistory` not tested!
    - [ ] `HasSIDHistory`
  - [ ] `Sessions`
    - [ ] List users with RPC
- Users
  - [ ] `Properties` : `sfupassword`
- OUs & Domains
  - [ ] `GPOChanges`
    - [ ] `LocalAdmins`
    - [ ] `RemoteDesktopUsers`
    - [ ] `DcomUsers`
    - [ ] `PSRemoteUsers`

## Optimization
- [x] Log level (info,debug,trace)
- [x] Error management
- [x] **add_childobjects_members()** ChildObject function in checker/bh_41.rs
- [x] **replace_guid_gplink()** gplinks function in checker/bh_41.rs
- [x] **add_domain_sid()** gplinks function in checker/bh_41.rs

# :link: Links

- Blog post: [https://www.opencyber.com/rusthound-data-collector-for-bloodhound-written-in-rust/](https://www.opencyber.com/rusthound-data-collector-for-bloodhound-written-in-rust/)
- BloodHound.py: [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)
- SharpHound:  [https://github.com/BloodHoundAD/SharpHound](https://github.com/BloodHoundAD/SharpHound)
- BloodHound: [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)
- BloodHound docs: [https://bloodhound.readthedocs.io/en/latest/index.html](https://bloodhound.readthedocs.io/en/latest/index.html)
- GOADv2: [https://github.com/Orange-Cyberdefense/GOAD](https://github.com/Orange-Cyberdefense/GOAD)