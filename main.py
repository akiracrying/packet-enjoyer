import sys
import socket
from scapy.all import *
import psutil
from scapy.layers.inet import TCP, IP

from front import Ui_PacketGenerator
from PyQt5.QtWidgets import QApplication, QMainWindow, QListWidget


def checker(params):
    for value in params.values():
        if not value:
            return True
    return False


def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())


class PacketEnjoyer:
    class PacketFiller:

        def __init__(self, ui: Ui_PacketGenerator):
            self.src_ip = ui.
            self.src_port = 12345
            self.dest_ip = "192.168.1.200"
            self.dest_port = 80
            self.sequence_number = 1000
            self.acknowledgment_number = 0
            self.flags = "S"  # Устанавливаем флаг SYN
            self.data = b"Hello, server!"

    def __init__(self):
        self.app = QApplication(sys.argv)
        self.window = QMainWindow()
        self.ui = Ui_PacketGenerator()

    def __generate_tcp_packet(self):
        src_ip = "192.168.1.100"
        src_port = 12345
        dest_ip = "192.168.1.200"
        dest_port = 80
        sequence_number = 1000
        acknowledgment_number = 0
        flags = "S"  # Устанавливаем флаг SYN
        data = b"Hello, server!"

        ip_packet = IP(src=src_ip, dst=dest_ip)
        tcp_packet = TCP(sport=src_port, dport=dest_port, seq=sequence_number, ack=acknowledgment_number, flags=flags)
        packet = ip_packet / tcp_packet / data

        return packet

    def init_buttons(self):
        self.ui.startButton.clicked.connect(self.__generate_tcp_packet)

    def draw(self):
        self.ui.setupUi(self.window)
        self.ui.intSelect.addItems(get_network_interfaces())
        self.window.show()
        sys.exit(self.app.exec_())


def main():
    app = PacketEnjoyer()
    app.draw()


if __name__ == "__main__":
    main()
