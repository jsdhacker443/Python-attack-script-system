import base64, os

# 针对某个文件进行Base64转码并加密保存
def encrypt(filepath):
    with open(filepath, mode='rb') as file:
        data = file.read()

    source = base64.b64encode(data).decode()
    # 加密算法：大小写字母右移5位
    dest = ''
    for c in source:
        dest += chr(ord(c)+5)

    # 将加密字符串保存到文件中
    with open(filepath + '.enc', mode='w') as file:
        file.write(dest)

    # 删除原始文件
    os.remove(filepath)

# 解密
def decrypt(filepath):
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

if __name__ == '__main__':
    encrypt('./test.jpg')
    # encrypt('./test.pdf')

    # decrypt('./test.jpg.enc')
    # decrypt('./test.pdf.enc')

# 课堂练习：遍历目录，对某些目录下的关键文件：Word, XLS, XLS, DOCX, PPT, PPTX，RAR，JPG，PNG，TXT，PDF
# 也可以对文件的一部分进行加密，将Base64字符串分成三部分，fisrt[0:200], middle[200:500]加密, last[500:]