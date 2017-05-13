import socket
from pprint import *

dns_dic = dict() # <����-ip>�ֵ�

def crt_dns_dic():
    """����<����-ip>�ֵ�"""
    global dns_dic # <����-ip>�ֵ�
    with open('dnsrelay.txt', 'r') as f:
        text = f.readlines()
        for line in text:
            ip_domain = line.split()
            if len(ip_domain):
                dns_dic[ip_domain[1]] = ip_domain[0]
            


class Mes():
    """����"""
    def __init__(self, data):
        self.data = data # �ֽڴ�
        self.data_array = bytearray(self.data) # �ֽ�����
        self.qr = self.get_qr() # QR��0Ϊ��ѯ��1Ϊ��Ӧ
        self.id = self.get_id() # ID
        self.domain = self.get_domain()
        self.name = self.get_name()

        # ��ѯ��
        if self.qr == 0:
            pass
        self.domain = self.get_domain() # ����
        # self.ip = self.get_ip()
 
    def get_qr(self):
        return self.data[2] // 0x80
        
    def get_id(self):
        return self.data[0:2]


    def get_domain(self):
        """�������"""
        i = 12  # question section �ӵ�13�ֽڿ�ʼ
        domain = ''
        while self.data_array[i] != 0:
            num = int(self.data_array[i])  # �ַ�����
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
        """���ͻظ�����"""
        # ���ֵ����и�����
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
        # ����һ������
        data, addr = s.recvfrom(1024)  # ���ձ���
        mm = Mes(data)
        mm.get_ans()
        


