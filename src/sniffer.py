import os

from scapy.all import sniff, Raw, ifaces
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
from scapy.packet import Packet


def sniffing_firewall(packet: Packet) -> None:
    if packet.haslayer(HTTPRequest):
        print(packet)


def main() -> None:
    iface = ifaces.dev_from_index(1)
    sniff(
        prn=sniffing_firewall,
        iface=iface,
        filter='port 8000',
        session=TCPSession
    )


if __name__ == '__main__':
    main()