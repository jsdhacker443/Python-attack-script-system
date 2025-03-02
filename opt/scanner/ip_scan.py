
from scapy.layers.l2 import ARP
from scapy.all import *

# 配置日志记录的级别为 ERROR
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# 在公网上，不会进行IP扫描，通常是明确目标IP而进行端口扫描
# 如果要进行内网渗透，则必须要知道有哪些IP地址是存活的，可访问的，进而再进行端口扫描
# IP地址工作在IP层，ICMP，还有ARP协议也存在IP信息
# 先使用 ping 命令进行IP探测，但是此扫描方式存在Bug，一旦防火墙禁止ICMP，那么扫描结果失效
def ping_ip(start):
    for i in range(start,start+10):
        ip = f'192.168.19.{i}'
        output = os.popen(f'ping -n 1 -w 100 {ip}').read()
        if 'TTL=' in output:
            print(f"{ip} online")

        # output = os.popen(f'ping -n 1 -w 100 {ip} | findstr TTL=').read()
        # if len(output) > 0:
        #     print(f"{ip} online")

# 如何使用别的方式，让防火墙不存在封锁的行为？了解一下ARP协议，pip install scapy
# 构造的scapy底层数据包pkg = ARP(pdst=ip)/IP( dst=ip)/TCP(dport=80)
def scapy_ip(start):
    for i in range(start, start+10):
        ip = f'192.168.19.{i}'
        try:
            pkg = ARP(psrc='192.168.19.1', pdst=ip)
            reply = sr1(pkg, timeout=3, verbose=False)
            print(reply[ARP].hwsrc)
            print(f"{ip} 在线")
        except :
            pass
if __name__ == '__main__':
    # 多线程分任务IP扫描
    for i in range(1, 255, 10):
        threading.Thread(target=ping_ip, args=(i,)).start()       # 基于ping命令
        # threading.Thread(target=scapy_ip, args=(i,)).start()      # 基于scapy发包