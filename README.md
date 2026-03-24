# Packet Sniffer — Usage Guide

## Basic Usage
```bash
sudo ./target/debug/netsniff -i <interface> -c <count>
```

---

## Commands

### List Available Interfaces
Run without `-i` to see all available network interfaces:
```bash
sudo ./target/debug/netsniff
```

---

### Capture on a Specific Interface
```bash
sudo ./target/debug/netsniff -i wlan0
sudo ./target/debug/netsniff --interface wlan0
```
`-i` and `--interface` are interchangeable.

---

### Capture a Specific Number of Packets
```bash
sudo ./target/debug/netsniff -i wlan0 -c 50
sudo ./target/debug/netsniff -i wlan0 --count 50
```
Default is `10` if `-c` is not specified.

---

### Capture Unlimited Packets
```bash
sudo ./target/debug/netsniff -i wlan0 -c 0
```
`0` means run forever. Use `Ctrl+C` to stop.

---

### Combine Interface + Count
```bash
sudo ./target/debug/netsniff -i eth0 -c 100
sudo ./target/debug/netsniff --interface eth0 --count 100
```

---

### Help & Version
```bash
./target/debug/netsniff --help
./target/debug/netsniff --version
```
These don't require `sudo` since they don't open any sockets.

---

### Run the Release Build
For actual use — faster and more optimized than the debug build:
```bash
cargo build --release
sudo ./target/release/netsniff -i wlan0 -c 20
```

---

## Common Interfaces

| Interface | Description          |
|-----------|----------------------|
| `wlan0`   | WiFi                 |
| `eth0`    | Ethernet             |
| `lo`      | Loopback (localhost) |
| `tun0`    | VPN tunnel           |

> Run without `-i` first to see exactly what's available on your machine.

---

## Notes
- Raw packet capture requires root privileges on Linux. Always prefix with `sudo`.
- `libpcap-dev` must be installed: `sudo apt install libpcap-dev`
- Use `Ctrl+C` to stop unlimited captures (`-c 0`).
