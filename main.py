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
            self.src_ip = ui.SRCIP.text()
            self.src_port = ui.SRCport.text()
            self.dest_ip = ui.DSTSIP.text()
            self.dest_port = ui.DSTport.text()
            self.sequence_number = ui.SEQnum.text()
            self.acknowledgment_number = ui.ACKnum.text()
            self.data = ui.DATAINPUT.text()

            # flags
            self.flags = ""

            self.syn = ui.SYN_check.isChecked()
            self.ack = ui.ACK_check.isChecked()
            self.psh = ui.PSH_check.isChecked()
            self.fin = ui.FIN_check.isChecked()
            self.rst = ui.RST_check.isChecked()
            self.urg = ui.URG_check.isChecked()
            self.ecn = ui.ECN_check.isChecked()
            self.cwr = ui.CWR_check.isChecked()

            if self.syn:
                self.flags += "S"
            if self.ack:
                self.flags += "A"
            if self.psh:
                self.flags += "P"
            if self.fin:
                self.flags += "F"
            if self.rst:
                self.flags += "R"
            if self.urg:
                self.flags += "U"
            if self.ecn:
                self.flags += "E"
            if self.cwr:
                self.flags += "C"

    def __init__(self):
        self.app = QApplication(sys.argv)
        self.window = QMainWindow()
        self.ui = Ui_PacketGenerator()

    def __generate_tcp_packet(self):
        p = self.PacketFiller(self.ui)

        ip_packet = IP(src=p.src_ip, dst=p.dest_ip)
        tcp_packet = TCP(
            sport=p.src_port,
            dport=p.dest_port,
            seq=p.sequence_number,
            ack=p.acknowledgment_number,
            flags=p.flags
        )
        tcp_packet.load = p.data
        generated_packet = ip_packet / tcp_packet / p.data
        print(tcp_packet)
        for i in range(0, self.ui.COUNT):
            sendp(tcp_packet, iface=self.ui.intSelect.currentText())

        tcp_packet.show()
        return generated_packet

    def init_buttons(self):
        self.ui.startButton.clicked.connect(self.__generate_tcp_packet)

    def draw(self):
        self.ui.setupUi(self.window)
        self.init_buttons()
        self.ui.intSelect.addItems(get_network_interfaces())
        self.window.show()
        sys.exit(self.app.exec_())


def main():
    app = PacketEnjoyer()
    app.draw()


if __name__ == "__main__":
    main()
