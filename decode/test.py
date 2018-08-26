# -*- coding: utf-8 -*-

from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64

# 加密解密：公钥加密，私钥解密
#
# 签名验签：私钥签名，公钥验签
#
# 生成 private key and pulic key
print "1、生成 private key and pulic key"

# 伪随机数生成器
random_generator = Random.new().read
# rsa算法生成实例
rsa = RSA.generate(1024, random_generator)

# master的秘钥对的生成
private_pem = rsa.exportKey()

with open('master-private.pem', 'w') as f:
    f.write(private_pem)

public_pem = rsa.publickey().exportKey()
with open('master-public.pem', 'w') as f:
    f.write(public_pem)

# ghost的秘钥对的生成
private_pem = rsa.exportKey()
with open('ghost-private.pem', 'w') as f:
    f.write(private_pem)

public_pem = rsa.publickey().exportKey()
with open('ghost-public.pem', 'w') as f:
    f.write(public_pem)

# 加密和解密
print "2、加密和解密"
# Master使用Ghost的公钥对内容进行rsa 加密

message = 'hello ghost, this is a plian text'
print "message: " + message
with open('ghost-public.pem') as f:
    key = f.read()
    rsakey = RSA.importKey(key)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(message))
    print "加密（encrypt）"
    print cipher_text

# Ghost使用自己的私钥对内容进行rsa 解密

with open('ghost-private.pem') as f:
    key = f.read()
    rsakey = RSA.importKey(key)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    text = cipher.decrypt(base64.b64decode(cipher_text), random_generator)

    print "解密（decrypt）"
    print "message:" + text

    assert text == message, 'decrypt falied'

# 签名与验签
print "3、 签名与验签"

# Master 使用自己的私钥对内容进行签名
print "签名"
with open('master-private.pem') as f:
    key = f.read()
    rsakey = RSA.importKey(key)
    signer = Signature_pkcs1_v1_5.new(rsakey)
    digest = SHA.new()
    digest.update(message)
    sign = signer.sign(digest)
    signature = base64.b64encode(sign)

print signature

print "验签"
with open('master-public.pem') as f:
    key = f.read()
    rsakey = RSA.importKey(key)
    verifier = Signature_pkcs1_v1_5.new(rsakey)
    digest = SHA.new()
    # Assumes the data is base64 encoded to begin with
    digest.update(message)
    is_verify = verifier.verify(digest, base64.b64decode(signature))

print is_verify
