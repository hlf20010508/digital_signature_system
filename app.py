import os
import methods
import config
import errors

class App:
    def __init__(self):
        self.name = None  # 用户名
        self.pubkey = None  # 公钥
        self.privkey = None  # 私钥

        self.init()

    def init(self):
        opt = int(input('0 登录 1 注册 '))  # 是否已创建密钥，若已创建则直接使用
        if opt==1:
            self.register()
        elif opt == 0:
            self.login()
        else:
            errors.option_erro()
            self.init()

    def option(self):  #选项菜单
        print()
        print('1.签名')
        print('2.验证签名')
        print('3.加密')
        print('4.解密')
        print('5.导出密钥')
        print('0.退出')
        print('请输入：', end='')
        opt = int(input())
        if opt == 1:
            self.sign()
        elif opt == 2:
            self.verify()
        elif opt == 3:
            self.encrypt()
        elif opt == 4:
            self.decrypt()
        elif opt == 5:
            self.export_key()
        elif opt == 0:
            self.exit()
        else:
            print()
            errors.option_erro()
            self.option()

    def run(self):
        self.option()

    def login(self):  # 使用已创建的密钥，使用用户名来区别不同用户的密钥
        self.name = input('请输入用户姓名：')
        self.pubkey = methods.read_pubkey(os.path.join(
            config.pubkey_path, self.name+config.pubkey_end))
        self.privkey = methods.read_privkey(os.path.join(
            config.privkey_path, self.name+config.privkey_end))
        print('登录成功！')

    def register(self):  # 生成密钥，使用用户名来命名密钥
        opt = int(input('0 导入密钥 1 生成密钥 '))
        self.name = input('请输入用户姓名：')
        if opt:
            length = int(input('请输入密钥大小：'))
            self.pubkey, self.privkey = methods.creat_key(self.name, length)
        else:
            self.import_key()
        print('注册成功！')

    def sign(self):  # 签名
        flag = int(input('是否生成独立签名文件？ 0 否 1 是 '))
        merge = False
        if not flag:
            merge = True
        file_path = input('请输入文件路径：')
        try:
            file = methods.read_file(file_path)
        except:
            errors.file_path_erro()
            self.sign()
        file_save_path = input('请输入签名文件保存路径：')
        text = methods.rsaSign(file, self.privkey, merge=merge)
        methods.save_file(file_save_path, text)
        print('签名成功！')
        self.option()

    def verify(self):  # 验证签名
        file_path = input('请输入文件路径：')
        try:
            file = methods.read_file(file_path)
        except:
            errors.file_path_erro()
            self.verify()
        signature_path = input('请输入签名文件路径：')

        try:
            signature = methods.read_file(signature_path)
        except:
            errors.signature_path_erro()
            self.verify()
        if methods.rsaVerify(file, signature, self.pubkey):
            print('认证成功！')
        else:
            print('认证失败！')
        self.option()

    def encrypt(self):  #加密
        file_path = input('请输入文件路径：')
        try:
            file = methods.read_file(file_path)
        except:
            errors.file_path_erro()
            self.decrypt()

        file_save_path = input('请输入加密文件保存路径：')

        text = methods.rsaEncrypt(file, self.pubkey)
        methods.save_file(file_save_path, text)
        print('加密成功！')
        self.option()

    def decrypt(self):  # 解密
        file_path = input('请输入文件路径：')
        try:
            file = methods.read_file(file_path)
        except:
            errors.file_path_erro()
            self.decrypt()

        file_save_path = input('请输入解密文件保存路径：')

        try:
            text = methods.rsaDecrypt(file, self.privkey)
            methods.save_file(file_save_path, text)
            print('解密成功！')
        except:
            print('解密失败！')
        self.option()
    
    def import_key(self):  #导入密钥
        pubkey_path = input('请输入公钥文件路径：')
        privkey_path = input('请输入私钥文件路径：')
        pubkey = methods.read_pubkey(pubkey_path)
        privkey = methods.read_privkey(privkey_path)
        pub_text=pubkey.save_pkcs1()
        priv_text=privkey.save_pkcs1()
        methods.save_file(os.path.join(config.pubkey_path, self.name+'_pubkey.pem'),pub_text)
        methods.save_file(os.path.join(config.privkey_path, self.name+'_privkey.pem'),priv_text)

    def export_key(self):  #导出密钥
        path=input('请输入导出目录：')
        pub_text = self.pubkey.save_pkcs1()
        priv_text = self.privkey.save_pkcs1()
        methods.save_file(os.path.join(path, self.name+'_pubkey.pem'),pub_text)
        methods.save_file(os.path.join(path, self.name+'_privkey.pem'),priv_text)
        print('导出成功！')
        self.option()

    def exit(self):
        os._exit(1)


if __name__ == '__main__':
    App().run()
