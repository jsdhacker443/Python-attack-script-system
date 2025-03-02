import re, requests, random
import time

# 基于一些错误的源内容，对其进行优化，并下载和保存网页
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

if __name__ == '__main__':
    download_page()

