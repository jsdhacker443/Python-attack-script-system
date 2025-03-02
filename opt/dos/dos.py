import os, time
from collections import Counter

# 第一步：先采集跟DOS攻击关联度较高的数据

# 1、采集CPU的平均负载
def get_cpu_load():
    # 利用Python处理字符串的方式
    uptime = os.popen('uptime').read()
    uptime = uptime.replace(": ", ",")
    cpu_load = float(uptime.split(",")[-3])

    # 利用awk命令来提取CPU负载
    cpu_load = os.popen("uptime | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'").read()
    cpu_load = float(cpu_load)

    return cpu_load

# 2、采集netstat -ant的连接数量
def get_conn_count():
    netstat = os.popen('netstat -ant | wc -l').read()
    return int(netstat)

# 3、采集队列长度
def get_queue_size():
    # ss -lnt | grep :3306 | awk '{print $2}'
    sslnt = os.popen("ss -lnt | grep :3306").read()
    recvq = int(sslnt.split()[1])
    sendq = int(sslnt.split()[2])
    return recvq, sendq

# 4、采集连接数量最多的IP地址
def get_most_ip():
    result = os.popen('netstat -ant | grep :3306').read()
    line_list = result.split('\n')
    ip_list = []
    for line in line_list:
        try:
            temp_list = line.split()
            ip = temp_list[4].split(':')[0]
            ip_list.append(ip)
        except:
            pass

    dict = Counter(ip_list)
    most_ip = dict.most_common(1)
    return most_ip[0][0]

# 5、调用firewall-cmd防火墙命令封锁攻击源IP地址
def firewall_ip(ip):
    os.system(f"systemctl start firewalld")
    result = os.popen(f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} port port=3306 protocol=tcp reject'").read()
    if 'success' in result:
        print(f"已经成功将可疑攻击源 {ip} 进行封锁，流量将不再进入.")
    else:
        print(f"对可疑攻击源 {ip} 进行封锁时失败，转为人工处理.")
# 防火墙命令
# 删除规则：firewall-cmd --remove-rich-rule='rule family=ipv4 source address=192.168.19.1 port port=3306 protocol=tcp reject'
# 查看规则列表：firewall-cmd --list-all
# 添加防火墙放行端口：firewall-cmd --add-port=3306/tcp --permanent
# 重新加载防火墙 firewall-cmd --reload
# Kali Dos攻击程序代码
# hping3 --flood -S -p 8080 192.168.19.130
# vi编辑，双击dd删除一行全部删除使用rm -f dos.py
if __name__ == '__main__':
    while True:
        cpu = get_cpu_load()
        conn = get_conn_count()
        recvq, sendq = get_queue_size()
        most_ip = get_most_ip()
        print(f"CPU-Load: {cpu}, TCP Conn: {conn}, TCP Queue: {recvq, sendq}")

        # 对采集到的数据进行判断，并进行预警提醒
        if cpu > 50 or conn > 500 or recvq > sendq - 10:
            print(f"当前系统TCP连接负载和CPU使用率过高，存在DOS攻击的可能性，可疑IP地址为：{most_ip}.")
            firewall_ip(most_ip)

        time.sleep(2)