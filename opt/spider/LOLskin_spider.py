import requests         #pip install requests
import re
from time import sleep
import os

#全部英雄url:查看页面信息，找到英雄字典文件champion.js
all_hero_url = 'https://lol.qq.com/biz/hero/champion.js'

#设置头部的代理端，包含浏览器和操作系统等信息
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54'}

#request的get方法，以指定的header访问url
all_hero_js_resp = requests.get(all_hero_url,headers=headers)

#正则表达式匹配英雄名字
all_hero_name = re.findall(r'"\d+?":"(\w+?)"',all_hero_js_resp.text)
#r''是匹配内容模板，括号是获取的内容，\d是数字，+是多个，？是非贪婪匹配

#循环遍历全部英雄
for n in all_hero_name:
    sleep(1)            #让系统休眠1秒，避免被检测出来是爬虫被屏蔽IP

    #获取某位英雄url信息
    hero_info_js_url = f"https://lol.qq.com/biz/hero/{n}.js"   # f作用是让{}起到占位符的效果，不然{n}被认为是字符串
    hero_info_js_resp = requests.get(hero_info_js_url,headers=headers)
    hero_info_js = hero_info_js_resp.text
    #正则表达式匹配皮肤id
    skin_ids = re.findall(r'"id":"(\d+?)"',hero_info_js)
    #正则表达式匹配皮肤名称
    skin_names = re.findall(r'"name":"(.+?)".+?"chrom',hero_info_js)  #.是指所有的非空字符

    #循环下载皮肤，并且保存图片名为皮肤名
    for id,name in zip(skin_ids,skin_names):
        img_url = f'https://game.gtimg.cn/images/lol/act/img/skin/big{id}.jpg'
        #发送请求
        img_resp = requests.get(img_url,headers=headers)

        #解决中文编码问题，因为json文件里中文名是unicode格式
        name = name.encode().decode('unicode_escape')

        #解决皮肤名称里的‘\’引起的错误
        name = name.replace('/','')
        name = name.replace('\\','')
        print(f'正在爬取{n}的{name}皮肤')

        #创建文件夹分类保存每个英雄的多个皮肤
        if not os.path.exists(f'./img/{n}'):
            os.makedirs(f'./img/{n}')
        with open(f'./img/{n}/{name}.jpg','wb') as f:
            f.write(img_resp.content)
            sleep(1)