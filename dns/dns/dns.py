import socket
from pprint import *

dns_dic = dict() # <域名-ip>字典

def crt_dns_dic():
    """建立<域名-ip>字典"""
    global dns_dic # <域名-ip>字典
    with open('dnsrelay.txt', 'r') as f:
        text = f.readlines()
        for line in text:
            ip_domain = line.split()
            if len(ip_domain):
                dns_dic[ip_domain[1]] = ip_domain[0]
            


class Mes():
    """报文"""
    def __init__(self, data):
        self.data = data # 字节串
        self.data_array = bytearray(self.data) # 字节数组
        self.qr = self.get_qr() # QR：0为查询，1为响应
        self.id = self.get_id() # ID
        self.domain = self.get_domain()
        self.name = self.get_name()

        # 查询报
        if self.qr == 0:
            pass
        self.domain = self.get_domain() # 域名
        # self.ip = self.get_ip()
 
    def get_qr(self):
        return self.data[2] // 0x80
        
    def get_id(self):
        return self.data[0:2]


    def get_domain(self):
        """获得域名"""
        i = 12  # question section 从第13字节开始
        domain = ''
        while self.data_array[i] != 0:
            num = int(self.data_array[i])  # 字符个数
            for byte in self.data_array[i + 1: i + 1 + num]:
                domain += chr(byte)
            i += num + 1
            domain += '.'
        domain = domain[0:-1]
        return domain

    def get_name(self):
        
        i = 12
        name = b''
        while self.data_array[i] != 0:
            num = int(self.data_array[i])
            name += bytes(self.data[i: i + 1 + num])
            i += num +1
        return name

        
    def get_ans(self):
        """发送回复报文"""
        # 若字典中有该域名
        if self.domain in dns_dic:
            send_back()
    
    def send_back(self):
        global s, addr
        ip_parts = dns_dic[self.domain].split('.')
        m_head = self.id + b'\x00' + b'\x00' + b'\x00\x00' + b'\x00\x01'+\
                           b'\x00\x00' + b'\x00\x00'
        
        m_record = self.name + b'\x00\x01' + b'\x00\x01' + b'\x00\x02\xA3\x00' +\
                               b'\x00\x04' + bytes(ip_parts)
        m_msg = m_head + m_record
        s.sendto(m_msg, addr)
        

        
        


if __name__ == '__main__':
    
    crt_dns_dic()
    #pprint(dns_dic)
    addr = ('', 53)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(addr)
    print('Waiting...')
    while True:
        # 接收一个数据
        data, addr = s.recvfrom(1024)  # 接收报文
        mm = Mes(data)
        mm.get_ans()
        


