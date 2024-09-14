#!/usr/bin/env pyhthon
#requirement pip install netfilterqueue

import netfilterqueue



def process_packet(packet):
    print(packet)
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
