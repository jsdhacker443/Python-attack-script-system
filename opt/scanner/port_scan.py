
from scapy.layers.inet import IP, TCP
from scapy.all import *

# 基于socket多线程进行端口扫描
# 对目标IP进行端口扫描，尝试连接目标IP和端口，如果连接成功，说明端口开放，否则未开放。
def socket_port_thread(ip, start):
    for port in range(start, start+100):
        try:
            s = socket.socket()
            s.settimeout(0.1)       # 设置无法连接情况下超时时间，提升扫描效率
            s.connect((ip, port))
            print(f"端口：{port} 可用.")
            s.close()
        except:
            pass

def scapy_port(ip):
    # 通过指定源IP地址，可以实现IP欺骗，进而导致半连接，此类操作也可以用于Flags参数定义上
    # pkg = IP(src='192.168.115.123', dst=ip)/TCP(dport=80, flags='SA')
    list = [7, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 81, 88, 109, 110, 113, 119, 123, 135, 135,
            137, 138, 139, 143, 161, 162, 179, 194, 220, 389, 443, 445, 465, 513, 520, 520, 546, 547,
            554, 563, 631, 636, 991, 993, 995, 1080, 1194, 1433, 1434, 1494, 1521, 1701, 1723, 1755,
            1812, 1813, 1863, 3269, 3306, 3307, 3389, 3544, 4369, 5060, 5061, 5355, 5432, 5671, 5672, 6379,
            7001, 8080, 8081, 8088, 8443, 8883, 8888, 9443, 9988, 9988, 15672, 50389, 50636, 61613, 61614]
    for port in list:
        try:
            pkg = IP(src='192.168.19.1', dst=ip) / TCP(dport=port, flags='S')
            reply = sr1(pkg, timeout=1, verbose=False)
            # print(reply[TCP].flags)
            if reply[TCP].flags == 0x12:
                # if int(reply[TCP].flags) == 18:
                print(f'端口 {port} 开放')
        except:
            pass






if __name__ == '__main__':

    #基于socket的多线程分任务全端口扫描
    for i in range(1, 65536, 100):    # 650多个线程每个扫100个端口
        threading.Thread(target=socket_port_thread, args=('192.168.19.132', i)).start()

    # 基于scapy的常用端口扫描
    # scapy_port("192.168.19.132")