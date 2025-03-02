from Crypto.Cipher import DES,AES
import binascii
import base64
from hashlib import md5
import rsa
from binascii import b2a_hex, a2b_hex

def my_md5(data):
    new_md5 = md5()
    new_md5.update(data.encode(encoding='utf-8'))
    print(new_md5.hexdigest())

def EnCrypt_Base64(data):
    res = base64.b64encode(data.encode('utf-8'))
    print("Base64加密：" + res.decode('utf-8'))

def DeCrypt_Base64(encrypt_text):
    res = base64.b64decode(encrypt_text.encode('utf-8'))
    print("Base64解密：" + res.decode('utf-8'))

def EnCrypt_DES(key,data):
    MyDes = DES.new(key,DES.MODE_ECB)       #使用DES的ECB加密
    data = data + (8 - len(data)%8)*'='     #加密明文也要为8的倍数,其实是key的倍数
    print("明文补足为：" + data)
    encrypt_text = MyDes.encrypt(data.encode())
    encrypt_res = binascii.b2a_hex(encrypt_text)
    print("DES加密：" + str(encrypt_res))

def DeCrypt_DES(key,encrypt_res):
    MyDes = DES.new(key,DES.MODE_ECB)
    encrypt_text = binascii.a2b_hex(encrypt_res)
    decrypt_res = MyDes.decrypt(encrypt_text)
    print("DES解密："+ str(decrypt_res))

def EnCrypt_AES(key,data):
    data = data + (16 - len(data) % 16) * '='  # 加密明文要为16的倍数,其实是key的倍数
    MyAes = AES.new(key,AES.MODE_ECB)
    encrypt_text = MyAes.encrypt(data.encode())
    encrypt_res = binascii.b2a_hex(encrypt_text)
    print(encrypt_res)

def Decrypt_AES(key,encrypt_res):
    MyAes = AES.new(key,AES.MODE_ECB)               #获取加密函数信息
    encrypt_text = binascii.a2b_hex(encrypt_res)    #内容转为hex
    decrypt_text = MyAes.decrypt(encrypt_text)      #调用解密函数
    print(decrypt_text)

def EnCrypt_RSA(pub,plain_text):
    encrypt = rsa.encrypt(plain_text.encode(), pub)
    encstr = b2a_hex(encrypt).decode()
    return encstr

def DeCrypt_RSA(priv,cipher_text):
    decrypt = rsa.decrypt(a2b_hex(cipher_text), priv)
    return decrypt

if __name__ == '__main__':

#DES
    MyKey = b'qwer1234'                     #密钥要为8位
    plain_text = 'nihaowww.baidu.com12345'
    cipher_text = b'4432b0ee54149825f6db48c87fb9ab65da52e89c878cfc4c'
    #EnCrypt_DES(MyKey,plain_text)
    #DeCrypt_DES(MyKey,cipher_text)

#AES
    MyKey2 = b'qwer1234qwer1234'           #AES则为8的倍数，至少2倍
    cipher_text2 = b'36e3b40094885788732111913ab4c17184c63a312c4c3b67be030d3c64d0785d'
    # EnCrypt_AES(MyKey2,plain_text)
    #Decrypt_AES(MyKey2,cipher_text2)

#RSA
    pub, priv = rsa.newkeys(2048)
    plain_text_rsa = 'hahaha,woshishei1'

    cipher_text_rsa = EnCrypt_RSA(pub,plain_text_rsa)
    # print(cipher_text_rsa)
    decrypto_text = DeCrypt_RSA(priv,cipher_text_rsa)
    # print(decrypto_text)
#Base64
    Base64_text = "bmloYW93d3cuYmFpZHUuY29tMTIzNDU="
    #EnCrypt_Base64(plain_text)
    #DeCrypt_Base64(Base64_text)

#MD5
    plain_text_md5 = '欢迎来到我的系统！'
    my_md5(plain_text_md5)