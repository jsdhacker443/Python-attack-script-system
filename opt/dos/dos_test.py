# 如何找到高频出现的IP地址

# 1、将netstat -ant 或 ss -nt 的输出结果进行解析，按行找到源IP
# 2、将找到的源IP地址添加到一个列表中
# 3、统计当前列表中，每一个IP地址出现的次数，找到最多的那一个

# 先定义列表
list = ['A', 'B', 'C','B','C','D','C','A','B','A','D','C','A','B','C','B','E','A','B','C','D','C']
# 利用字典的特性, dict = {'A':3, 'B': 5, 'C': 2}
dict = {}
for key in list:
    if key in dict.keys():
        dict[key] += 1
    else:
        dict[key] = 1
print(dict)     # {'A': 5, 'B': 6, 'C': 7, 'D': 3, 'E': 1}
# 对字典进行排序处理，将词频最高的好一个排在前面
sort = sorted(dict.values(), reverse=True)
print(sort)  # [7, 6, 5, 3, 1]
# 利用排序后的Value，根据Value反向查Key
for k, v in dict.items():
    if sort[0] == v:
        print(k)
        break

# 利用Python内置的Counter进行频率统计
from collections import Counter
list = ['A', 'B', 'C','B','C','D','C','A','B','A','D','C','A','B','C','B','E','A','B','C','D','C']
dict = Counter(list)
result = dict.most_common(3)
print(result)

# 统计IP地址
result = '''tcp        0      0 192.168.1.64:80         118.113.146.100:56176   FIN_WAIT2  
tcp        0      0 192.168.1.64:443        118.116.105.173:7726    ESTABLISHED
tcp        1     32 192.168.1.64:57174      101.226.212.27:443      LAST_ACK   
tcp        0      0 192.168.1.64:443        118.113.146.100:49857   FIN_WAIT2  
tcp        1      0 192.168.1.64:54080      101.91.34.103:443       CLOSE_WAIT 
tcp        0      0 192.168.1.64:80         36.44.108.45:11403      ESTABLISHED
tcp        0      0 192.168.1.64:80         118.113.147.48:56561    ESTABLISHED
tcp        0      0 192.168.1.64:80         118.113.146.101:53745   TIME_WAIT  
tcp        0      0 192.168.1.64:443        118.113.146.101:55167   ESTABLISHED
tcp        0      0 192.168.1.64:443        118.113.146.100:59926   ESTABLISHED
tcp        0      0 192.168.1.64:443        61.158.149.64:44690     ESTABLISHED
tcp        0      0 192.168.1.64:80         113.116.21.23:20404     ESTABLISHED'''
line_list = result.split('\n')
ip_list = []
for line in line_list:
    temp_list = line.split()
    ip = temp_list[4].split(':')[0]
    ip_list.append(ip)

print(ip_list)
dict = Counter(ip_list)
result = dict.most_common(1)
print(result[0][0])