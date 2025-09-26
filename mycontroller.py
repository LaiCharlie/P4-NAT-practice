import p4runtime_sh.shell as sh
import argparse
import threading
from scapy.all import *
import queue

class Controller:
    def __init__(self, device_id, grpc_addr):
        self.device_id   = device_id
        self.grpc_addr   = grpc_addr
        self.packet_in_q = queue.Queue()
        self.tuple_to_port = {}
        self.port_table    = {}
        self.nat_pool      = {}
        self.running = 1
        self._packet_in_thread = None

        for i in range(5001, 6025):
            self.port_table[i] = 0

    def log(self, *args):
        print(f'[{self.grpc_addr}]:', *args)

    def setUp(self):
        sh.setup(
            device_id=self.device_id,
            grpc_addr=self.grpc_addr,
            election_id=(0, 1),
            config=sh.FwdPipeConfig('build/nat.p4.p4info.txt', 'build/nat.json')
        )
        packetin = sh.PacketIn()
        def _handle_packet_in():
            while self.running:
                for pkt in packetin.sniff(timeout=0.01):
                    self.packet_in_q.put(pkt)
        self._packet_in_thread = threading.Thread(target=_handle_packet_in)
        self._packet_in_thread.start()
        self.log('setup success!')

        te = sh.TableEntry('MyIngress.ipv4_lpm')(action="MyIngress.ipv4_forward")
        te.match['hdr.ipv4.dstAddr'] = "10.0.3.3/32"
        te.action['dstAddr'] = "08:00:00:00:03:03"
        te.action['port']    = str(1)
        te.insert()

        te = sh.TableEntry('MyIngress.ipv4_lpm')(action="MyIngress.ipv4_forward")
        te.match['hdr.ipv4.dstAddr'] = "10.0.1.0/24"
        te.action['dstAddr'] = "08:00:00:00:01:00"
        te.action['port']    = str(2)
        te.insert()

        te = sh.TableEntry('MyIngress.ipv4_lpm')(action="MyIngress.ipv4_forward")
        te.match['hdr.ipv4.dstAddr'] = "10.0.2.0/24"
        te.action['dstAddr'] = "08:00:00:00:02:00"
        te.action['port']    = str(3)
        te.insert()

    def run(self):
        while self.running:
            try:
                pktin   = self.packet_in_q.get()
                payload = pktin.packet.payload
                port = int.from_bytes(pktin.packet.metadata[0].value, 'big')

                print('-'*20)
                pkt = Ether(_pkt=payload)
                src_mac = pkt.getlayer(Ether).src
                dst_mac = pkt.getlayer(Ether).dst

                if pkt.haslayer(IP):
                    src_ip   = pkt.getlayer(IP).src
                    dst_ip   = pkt.getlayer(IP).dst
                    protocol = pkt[IP].proto
                else:
                    pass

                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                if pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport

                if pkt.haslayer(ICMP):
                    print("ICMP type  :", pkt[ICMP].type)
                    print("ICMP code  :", pkt[ICMP].code)
                    print("ICMP cksum :", pkt[ICMP].chksum)
                    if pkt[ICMP].type == 8 or pkt[ICMP].type == 0:
                        print("ICMP id    :", pkt[ICMP].id)
                        print("ICMP seq   :", pkt[ICMP].seq)
                    

                print(f"src_mac:  {src_mac} , dst_mac: {dst_mac}")
                print(f"src_ip:   {src_ip}  , dst_ip: {dst_ip}, protocol: {protocol}")
                if pkt.haslayer(UDP) or pkt.haslayer(TCP):
                    print(f"src_port: {src_port}, dst_port: {dst_port}")

                if pkt.haslayer(UDP) or pkt.haslayer(TCP):
                    for i in range(5001, 6025):
                        if self.port_table[i] == 0:
                            port_snat = i
                            self.port_table[i] = 1
                            self.tuple_to_port[(src_ip, src_port, dst_ip, dst_port, protocol)] = port_snat
                            break

                    te = sh.TableEntry('MyIngress.inside_nat')(action="MyIngress.snat")
                    te.match['hdr.ipv4.srcAddr']  = str(src_ip)
                    te.match['hdr.port.srcPort']  = str(src_port)
                    te.match['hdr.ipv4.dstAddr']  = str(dst_ip)
                    te.match['hdr.port.dstPort']  = str(dst_port)
                    te.match['hdr.ipv4.protocol'] = str(protocol)
                    te.action['nat_ipaddr'] = "10.0.3.50"
                    te.action['port_num1']  = str(port_snat)
                    te.insert()

                    te = sh.TableEntry('MyIngress.outside_nat')(action="MyIngress.dnat")
                    te.match['hdr.ipv4.srcAddr']  = str(dst_ip)
                    te.match['hdr.port.srcPort']  = str(dst_port)
                    te.match['hdr.ipv4.dstAddr']  = "10.0.3.50"
                    te.match['hdr.port.dstPort']  = str(port_snat)
                    te.match['hdr.ipv4.protocol'] = str(protocol)
                    te.action['nat_ipaddr'] = str(src_ip)
                    te.action['port_num2']  = str(src_port)
                    te.insert()

                    print('\n')
                    print("tuple: ", (src_ip, src_port, dst_ip, dst_port, protocol))
                    print(f"ip_snat: 10.0.3.50, port_snat: {port_snat}")
                    print('-'*20)
                    print("tuple: ", (dst_ip, dst_port, "10.0.3.50", port_snat, protocol))
                    print(f"ip_dnat: {src_ip}, port_dnat: {src_port}")
                    print('\n')
                    print('='*20)
                
                elif pkt.haslayer(ICMP):
                    te = sh.TableEntry('MyIngress.icmp_snat')(action="MyIngress.nat_ping")
                    te.match['hdr.ipv4.srcAddr']      = str(src_ip)
                    te.match['hdr.ipv4.dstAddr']      = str(dst_ip)
                    te.match['hdr.icmp_echo.id'] = str(pkt[ICMP].id)
                    te.action['nat_ipaddr'] = "10.0.3.50"
                    te.insert()

                    te = sh.TableEntry('MyIngress.icmp_dnat')(action="MyIngress.nat_pong")
                    te.match['hdr.ipv4.srcAddr']      = str(dst_ip)
                    te.match['hdr.ipv4.dstAddr']      = "10.0.3.50"
                    te.match['hdr.icmp_echo.id'] = str(pkt[ICMP].id)
                    te.action['nat_ipaddr'] = str(src_ip)
                    te.insert()

                    print('\n')
                    print("tuple: ", (src_ip, dst_ip, pkt[ICMP].id))
                    print("ip_snat: 10.0.3.50")
                    print('-'*20)
                    print(f"tuple: {dst_ip}, 10.0.3.50, {pkt[ICMP].id}")
                    print(f"ip_snat: {src_ip}")
                    print('\n')
                    print('='*20)

                packet_out = sh.PacketOut()
                packet_out.payload = payload
                packet_out.metadata['ip_addr']  = "10.0.3.50"
                if pkt.haslayer(UDP) or pkt.haslayer(TCP):
                    packet_out.metadata['port_num'] = str(port_snat)
                else:
                    packet_out.metadata['port_num'] = "0"
                packet_out.send()
                pass

            except KeyboardInterrupt:
                self.running = 0


    def cleanUp(self):
        self.log('clean up')
        self.running = 0
        self._packet_in_thread.join()
        sh.teardown()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('device_id', type=int)
    parser.add_argument('grpc_addr', type=str)
    args = parser.parse_args()

    test_case = Controller(args.device_id, args.grpc_addr)
    test_case.setUp()
    test_case.run()
    test_case.cleanUp()
