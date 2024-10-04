# SpoofShifter

**SpoofShifter** is a lightweight and powerful DNS spoofing tool designed for ethical hackers and penetration testers. Written in Python, it leverages the `Scapy` library to manipulate DNS responses, allowing attackers to redirect DNS queries to a specified IP. When used in combination with ARP spoofing, SpoofShifter can perform effective Man-in-the-Middle (MitM) attacks, redirecting traffic seamlessly.

## Features
- Real-time DNS spoofing for specified domains.
- Efficient packet manipulation with `Scapy`.
- Ability to target specific DNS queries (e.g., redirect `www.google.com`).
- Easy integration with ARP spoofing for comprehensive network attacks.
- Lightweight and simple command-line interface.

## Requirements
Before running SpoofShifter, ensure that the following dependencies are installed:

### System Dependencies:
```bash
sudo apt-get update
sudo apt-get install libnetfilter-queue-dev
```

### Pyhton Libraries:
```bash
pip install netfilterqueue scapy
```

## Setup and Usage

1. Run iptables Rule: Redirect the network traffic to the NFQUEUE by running the following command:

```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```
2. Set Up ARP Spoofing: Run an ARP spoofing tool to intercept and manipulate traffic between the target and the router.

3. Execute SpoofShifter: Run the Python script to start DNS spoofing:

```bash
sudo python spoofshifter.py
```

The script will listen for DNS queries and spoof the specified domain (e.g., www.google.com) by returning a fake IP address.

## How it Works

- Packet Interception: SpoofShifter captures network packets using netfilterqueue and processes them.
- DNS Manipulation: It inspects DNS requests and modifies the response for specific domains to redirect them to a fake IP.
- Automatic Packet Correction: After modifying the DNS response, SpoofShifter recalculates the packet length and checksum to ensure the altered packets are valid.

## Code Breakdown

- **NetfilterQueue**: Used to capture and modify packets.
- **Scapy**: Handles packet manipulation and DNS spoofing.
- **Process Flow**: The script inspects DNS requests and sends spoofed responses to hijack the target's web traffic.

## Usage

1. **Clone the repository**:

```bash
git clone https://github.com/anishalx/spoofshifter.git
cd SpoofShifter
```

2. **Run the script**:

```bash
sudo python3 spoofshifter.py
```

3. **Stop iptables rule**: After the session, clear the iptables rule:

```bash
sudo iptables --flush
```

## Disclaimer

This tool is intended for educational purposes only. Do not use it on networks without proper authorization. The developers are not responsible for any misuse of this tool.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
