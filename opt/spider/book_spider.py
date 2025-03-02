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

if __name__=='__main__':
    for i in range(2020,2024):
        for j in range(1,26):
            url = 'http://bang.dangdang.com/books/bestsellers/01.00.00.00.00.00-year-{i}-0-1-{j}'.format(i=i,j=j)
            get_dangdang_info(i,url)
    print("正在保存到Excel，请稍候...")
    list_save()
    print("程序运行结束")