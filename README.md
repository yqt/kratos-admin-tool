# Overview

An admin tool for managing server-side of shadowsocks-libev for multi-user(config) including config and traffic management.

## Note

1. No unit tests yet. Work with Python 2.7.

# Usage

1. `pip install -r requirements.txt`
1. `cp config/config.py.sample config/config.py`
1. Generate private key and certificate for gPRC server.
1. `mkdir WOKRING_DIR_FOR_SS`
1. edit field of `config` in `config/config.py`
1. run server with `python start_start_server.py`(root privilege is required for configuring iptables)
