import sys,random
import time
import itertools

def main():
    words = "1234567890"
    temp = itertools.permutations(words,8)  #复杂度3

    #生成字典项目写入文件
    passwords = open("dict.txt","a")
    for item in temp:
        passwords.write("".join(item))
        passwords.write("".join("\n"))
    passwords.close()

if __name__ == '__main__':
    main()