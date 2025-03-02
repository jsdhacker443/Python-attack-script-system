import requests

# 自行实现一个HTML实体字符转换功能
def str_html(source):
    result = ''
    for c in source:
        result += '&#x' + hex(ord(c)) + ';'
    return result.replace('0x', '')

# 从响应中检测payload是否有效
def check_resp(response, payload, type):
    index = response.find(payload)
    prefix = response[index-2:index-1]
    if type == 'Normal' and prefix != '=' and index >= 0:
        return True
    elif type == 'Prop' and prefix == '=' and index >= 0:
        return True
    elif index >= 0:
        return True

    return False

# 实现XSS扫描的主功能
def xss_scan(location):
    url = location.split('?')[0]
    param = location.split('?')[1].split('=')[0]

    with open('../dict/xss-payload.txt') as file:
        payload_list = file.readlines()

    for payload in payload_list:
        type = payload.strip().split(':', 1)[0]
        payload = payload.strip().split(':', 1)[1]
        if type == 'Referer' or type == 'User-Agent' or type == 'Cookie':
            header = {type: payload}
            resp = requests.get(url=url, headers=header)
        else:
            resp = requests.get(url=url, params={param: payload})

        if check_resp(resp.text, payload, type):
            print(f"此处存在XSS漏洞：{payload}")


if __name__ == '__main__':
    # xss_scan('http://192.168.19.128/xss/level1.php?name=test')
    # xss_scan('http://192.168.19.128/xss/level2.php?keyword=test')
    # xss_scan('http://192.168.19.128/xss/level3.php?keyword=test')
    # xss_scan('http://192.168.19.128/xss/level4.php?keyword=test')
    # xss_scan('http://192.168.19.128/xss/level5.php?keyword=test')
    # xss_scan('http://192.168.19.128/xss/level11.php?keyword=test')
    source = 'http://192.168.19.128/xss/level17.php?arg01=aaa&arg02=bbb&arg03=ccc'
    url = source.split('?')[0]
    param_list = source.split('?')[1].split('&')
    # print(param_list)

    with open('../dict/xss-payload.txt') as file:
        payload_list = file.readlines()

    for payload in payload_list:
        params = {}
        for param in param_list:
            key = param.split('=')[0]
            params[key] = payload.strip().split(':', 1)[1]
        print(params)