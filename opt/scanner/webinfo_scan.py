from whois import whois
import json

# 查询域名的whois信息
def whois_info():
    result = whois('woniuxy.com')
    # print(result)
    dict = json.loads(str(result))
    print(dict)
    print(dict['registrar'])

if __name__ == '__main__':
    whois_info()