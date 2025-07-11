
# 🧵 netscan simple cli network scaner
**netscaner** is a command-line utility for real-time packet capturing and analysis, written in Go using [gopacket](https://github.com/google/gopacket). It works with a selected network interface, supports basic protocol decoding (TCP, UDP, ICMP, HTTP), and provides human-readable output, including hex+ASCII payload dumps similar to Wireshark.

## 🚀 Features
- Real-time packet capture from a network interface
- Protocol parsing: TCP, UDP, ICMP, HTTP, IP
- Readable output: IP addresses, ports, TCP flags, protocols
- Hex+ASCII payload dump (Wireshark-style)
- filter by protocol support
- Manual or automatic interface selection

## 📦 Dependencies
The utility uses the gopacket library to capture and analyze network traffic. It requires system dependencies to operate.
- pcpac
- any C compiler (i took gcc)
<details> <summary><strong>windows</strong></summary>
  <li>Install <a href="https://npcap.com/" >Npcap</a> (be sure to select the "WinPcap API-compatible Mode" option).</li>

</details>

<details> <summary><strong>Debian / Ubuntu / Kali</strong></summary>

```
sudo apt update
sudo apt install libpcap-dev
```
</details><details> <summary><strong>Fedora / CentOS / RHEL</strong></summary>

```
sudo dnf install libpcap-devel
```
</details> <details> <summary><strong>Arch / Manjaro</strong></summary>

```
sudo pacman -S libpcap
```

</details> <details> <summary><strong>Alpine Linux</strong></summary>

```
apk add libpcap-dev
```
</details>

## ⚙️ Build
```bash
git clone https://github.com/crewcrew23/netscan
cd netscan
make
```


## ▶️ Usage
```bash
sudo ./netscan -i <network interface> -f <protocol: optional>
```

## ⚙️ Command line options

| Flag         | Args       | Desc                                                                 |
|--------------|----------------|--------------------------------------------------------------------------|
| `-i`         | `<network interface>`  | Specifies the network interface to capture traffic on (e.g. `eth0`).     |
| `find-interfaces` |              | Lists available network interfaces. Used without `-i`.   |
| `-f`         | `<filter>`     | Filter by protocol: `tcp`, `udp`, `http`, `icmp`, `ip`, `ethernet`.You can specify several, separated by commas. |
| `-s`         | `<speed>`     | time in milisecond, the packages will be displayed at intervals at the specified time |

