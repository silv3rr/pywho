# PY-WHO!?

## /pai-hu/

Pzs-ng's sitewho ported to Python, uses SHM and glftpd's 'ONLINE' C struct.

Can be used as drop-in replacement.

![screenshot_1](docs/pywho1.png)

See [Screenshots.md](docs/Screenshots.md) for more examples

## New features

- fully themeable output including ..colors! and.. emoji💾😆
- set maxusers=-1 to auto get value from glftpd.conf
- adds same features as sitewho+2: userip/geoip fields
- adds spy mode, like gl_spy (test)
- only 1 py module dependency: sysv_ipc
- can also be build as single binary (using pyinstaller)

..also, now 200% slower!

## Usage

Same args and options as pzs-ng sitewho:

``` bash
./pywho                     # show all users
./pywho <username>          # show specified user
./pywho --raw               # show all users, display in raw format
./pywho --nbw               # show total stats for all users
./pywho --raw <username>    # show username, display in raw format

# newly added in pywho:

./phywho --help
./phywho --version
./phywho --spy              # spy mode (if enabled)
./phywho --xxl              # wide mode (if enabled)
```

## Installation

Requirements:

- Python3 and 'sysv_ipc' module, all other modules used are from standard lib
- only latest glftpd version 2.11a is supported (other versions untested)

__Choose 1 of the 3 installation methods below:__

### 1) OS packages

Seems CentOS does not have packages available, use venv or binaries instead (see below).

On Debian just install these packages and run the script:

- `apt install python3-sysv-ipc`
- `apt install python3-geoip2`  (optional)
- `git clone` this repo and run script: `./pywho.py`

### 2) Virtual Env

Alternatively use venv and pip:

``` bash
apt install python3-pip python3-venv
# -or-
yum install python3-pip python3-virtualenv

python3 -m venv venv
source venv/bin/activate
pip3 install sysv-ipc
pip3 install geoip2   # optional
```

Now 'git clone' this repo and run `./pywho.py`

_If you want to build sysv_ip from src see [https://github.com/osvenskan/sysv_ip](https://github.com/osvenskan/sysv_ipc)_

### 3) Binaries

[![Build pywho](https://github.com/silv3rr/pywho/actions/workflows/build.yml/badge.svg)](https://github.com/silv3rr/pywho/actions/workflows/build.yml)

If you do not want to install python modules, there's also a single executable file available for [download](../../releases).

Supported OS: CentOS 7, Debian 10, Debian 11 and Ubuntu 20.04

Get the files here: [Releases](../../releases)

## Configuration

Configure options in 'pywho.conf'. The ones on top are standard options, same as sitewho.conf. There are options added in new sections GEOIP, THEME, SPYMODE and XXLMODE. All options are explained at the bottom of conf. Make sure 'ipc_key' matches glftpd.

_Note that ss5, geoip, spy and xxl mode are disabled by default. To enable, edit pywho.py: `_WITH_GEOIP =  True` etc_

### Glftpd

Optionally add pywho as site_cmd in 'glftpd.conf' and/or replace binary(WHO) in 'ngBot.conf'. When running from glftpd, FLAGS is used to detect color(5) and seeallflags (same as pzs-ng sitewho).

## Build

To build the pywho binary yourself you need PyInstaller. You probably want to setup and activate a virtual env first (see above) then `pip install sysv-ipc pyinstaller`.

Now clone this repo and run build.sh, optionally add one or more of these args:

`build.sh _WITH_ALTWHO _WITH_SS5 _WITH_SPY _WITH_GEOIP _WITH_XXL`

The build script will check and warn about wrong python version and missing modules.

## Issues

- You get this message at runtime: `INTERNAL ERROR: cannot create temporary directory!`
    - Make sure your tmp dir exists with `+x` and `+t` (sticky bit).
    - When running chrooted from glftpd you'll need to `mkdir -m 1777 -p /glftpd/var/tmp`

- Enabling geoip2 is slow!
    - Yes.

- If geoip2 and spy mode are enabled you can run out of your free geoip queries
    - Max is 1000/day, ip lookups are cached in mem only and reset on restart of pywho

- No users are shown but they are actually logged in
    - Make sure users dont match 'hiddenusers' or 'hiddengroups' in pywho.conf

- "Spy mode sucks! it doesnt work, updates slowly, ignores key presses, text gets fucked up"
    - Well, yeah, it uses simple ansi escape sequences and select() stdin instead of curses and input events etc..

## Pywhy and how?

Just to see if its possible, ofc.. for all you pyfuckers

The sysv_ipc module does the heavy lifting rly. Unpacked data from shm segments buffer are wrapped in a namedtuple for readability and inserted to a list called 'user' e.g. `user[x].tagline`.

In general the code could probably be improved a lot and more 'pythonic' (more like moronic) and chunks are still just directly copied and converted from C.
