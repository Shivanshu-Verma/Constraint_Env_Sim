# Host-side DTLS Server

This folder contains a minimal WolfSSL-based DTLS 1.3 PSK server that pairs with the LiteX firmware demo under `boot/`.

## Build

The LiteX repository already vendors the WolfSSL sources used by the bare-metal
firmware. The provided `Makefile` reuses those sources and does **not** require a
system-wide WolfSSL installation. From this directory run:

```
make
```

The build drops objects in `host/build/` and produces the `server` binary in the
same folder. Use `make clean` to remove the artifacts.

## Run

1. Ensure the LiteX simulator is started with Ethernet enabled (for example `--with-ethernet --local-ip=192.168.1.50 --remote-ip=192.168.1.100`).
2. Configure the host TAP interface created by `litex_sim` with the same IP as the server (default `192.168.1.100`).
3. Launch the DTLS server from this directory:
   ```
   sudo ./server --listen 192.168.1.100 --port 5684
   ```
   Use `--debug` to enable verbose WolfSSL logging.

When the bare-metal client starts it will send a "ping from LiteX DTLS client" message. The server prints it and replies with "pong from host DTLS server".
