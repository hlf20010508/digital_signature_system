import rsa
import config
import os


def read_file(file_path):  # 读取文件
    file_object = open(file_path, 'rb')
    text = file_object.read()
    file_object.close()
    return text


def save_file(default_path, text):  # 保存文本
    file_object = open(default_path, 'wb')
    file_object.write(text)
    file_object.close()


def read_privkey(privkey_path):  # 读取私钥
    with open(privkey_path, 'rb') as privfile:
        p = privfile.read()
    privkey = rsa.PrivateKey.load_pkcs1(p)
    return privkey


def read_pubkey(privkey_path):  # 读取公钥
    with open(privkey_path, 'rb') as privfile:
        p = privfile.read()
    privkey = rsa.PublicKey.load_pkcs1(p)
    return privkey


def creat_key(name, Len):  # 生成密钥
    pubkey, privkey = rsa.newkeys(Len)
    pub_text = pubkey.save_pkcs1()  #将key保存为字符串
    priv_text = privkey.save_pkcs1()
    save_file(os.path.join(config.pubkey_path, name+'_pubkey.pem'), pub_text)  #将key字符串保存为文件
    save_file(os.path.join(config.privkey_path,name+'_privkey.pem'), priv_text)
    return pubkey, privkey


def rsaEncrypt(text, pubkey):  # 加密
    text = rsa.encrypt(text, pubkey)
    return text


def rsaDecrypt(text, privkey):  # 解密
    try:
        text = rsa.decrypt(text, privkey)
        return text
    except:
        return False


def rsaSign(text, privkey, merge=False):  # 签名
    sign = rsa.sign(text, privkey, 'MD5')
    if merge:
        text += b'\n-----BEGIN SIGNATURE-----\n'+sign + b'\n-----END SIGNATURE-----\n'  # 将签名加到文末
        return text
    else:
        return sign


def rsaVerify(text_origin, text_signature, pubkey):  # 验证签名
    sign = text_signature.split(b'\n-----BEGIN SIGNATURE-----\n')[-1].split(b'\n-----END SIGNATURE-----')[0] #尝试分离文末的签名
    try:
        rsa.verify(text_origin, sign, pubkey) #若能验证，说明原签名为在文末追加签名的方法
        return True
    except:
        try:
            rsa.verify(text_origin, text_signature, pubkey) #若不能验证，说明签名方法可能为生成独立签名文件，尝试验证
            return True
        except:  #若还是不能验证，说明验证失败
            return False
