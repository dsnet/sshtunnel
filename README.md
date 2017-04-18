# SSH tunnel proxy daemon #

## Introduction ##

This repository contains a simple implementation of a SSH proxy daemon used to
securely tunnel TCP connections in forward and reverse proxy mode.
This tool provides equivalent functionality to using the `ssh` command's
`-L` and `-R` flags.

Consider using [github.com/dsnet/udptunnel](https://github.com/dsnet/udptunnel)
if running behind a NAT that drops long-running TCP connections, but allows
UDP traffic to reliably pass through.

## Usage ##

Build the daemon:

```go get -u github.com/dsnet/sshtunnel```

Create a configuration file:

```javascript
{
	"KeyFiles": ["/path/to/key.priv"],
	"KnownHostFiles": ["/path/to/known_hosts"],
	"Tunnels": [{
		// Forward tunnel (locally binded socket proxies to remote target).
		"Tunnel": "bind_address:port -> dial_address:port",
		"Server": "user@host",
	}, {
		// Reverse tunnel (remotely binded socket proxies to local target).
		"Tunnel": "dial_address:port <- bind_address:port",
		"Server": "user@host",
	}],
}
```

The above configuration is equivalent to running the following:

```bash
ssh $USER@$HOST -i /path/to/key.priv -L $BIND_ADDRESS:$BIND_PORT:$DIAL_ADDRESS:$DIAL_PORT
ssh $USER@$HOST -i /path/to/key.priv -R $BIND_ADDRESS:$BIND_PORT:$DIAL_ADDRESS:$DIAL_PORT
```

Start the daemon (assuming `$GOPATH/bin` is in your `$PATH`):

```sshtunnel /path/to/config.json```
