import socket
from pprint import *
import sys
import getopt
import time

def crt_dns_dic(db_file):
    """建立<域名-ip>字典"""
    global dns_dic # <域名-ip>字典
    print('Try to load table "%s"' % (db_file), end=' ')
    try:
        with open(db_file, 'r') as f:
                text = f.readlines()
                for line in text:
                    ip_domain = line.split()
                    if len(ip_domain):
                        dns_dic[ip_domain[1]] = ip_domain[0]
    except IOError:
        print("... Fail")
        print("Error: db-file not found")
        sys.exit()
    print("... OK!")
    print(len(text), "names")

def id_gener():
    """顺序生成ID"""
    i = 0
    j = 0
    while True:
        j = j + 1
        if j >= 256:
            j = j % 256
            i = i + 1
        if i >= 256:
            i = i % 256
        yield bytes([i,j])

def record_count():
    i = 0
    while True:
        i = i + 1
        if i >= 100000:
            i = i % 100000
        yield i
            


class Mes():
    """报文"""
    def __init__(self, data, addr):
        self.data = data # 字节串
        self.data_array = bytearray(self.data) # 字节数组
        self.addr = addr #请求客户端地址
        self.qr = self.get_qr() # QR：0为查询，1为响应
        self.id = self.get_id() # ID
        self.domain = self.get_domain()
        self.name = self.get_name()
        self.q_sec = self.get_q_sec()
        self.domain = self.get_domain() # 域名

        # 调试模式
        global debug_mode, rc
        if debug_mode == 1:
            print(next(rc), end='\t')
            print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())), end='\t')
            print(self.domain)
        if debug_mode == 2:
            print("ID:", self.id, "QR:", self.qr, "Domain:", self.domain)
        
 
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

    def get_q_sec(self):
        """Question Section"""
        return self.data[12:]

    def get_name(self):
        """域名部分报文"""    
        i = 12
        name = b''
        while self.data_array[i] != 0:
            num = int(self.data_array[i])
            name += bytes(self.data[i: i + 1 + num])
            i += num +1
        name += b'\x00' # 以0结束
        return name

        
    def get_ans(self):
        """发送回复报文"""
        # 若字典中有该域名
        if self.domain in dns_dic:
            if dns_dic[self.domain] == "0.0.0.0":
                self.intercept() # 不良网站拦截功能
            else:
                self.response()
        else:
            self.query()
            pass

    def intercept(self):
        # 不良网站拦截
        global s
        ip_parts = list(map(int, dns_dic[self.domain].split('.')))
        m_head = self.id + b'\x85\x80' + b'\x00\x01' + b'\x00\x00'+\
                           b'\x00\x00' + b'\x00\x00'
        
        m_msg = m_head + self.q_sec
        s.sendto(m_msg, self.addr)    



    def response(self):
        #通过本地缓存记录回复
        global s
        ip_parts = list(map(int, dns_dic[self.domain].split('.')))
        m_head = self.id + b'\x85\x80' + b'\x00\x01' + b'\x00\x01'+\
                           b'\x00\x00' + b'\x00\x00'
        
        m_record = self.name + b'\x00\x01' + b'\x00\x01' + b'\x00\x02\xA3\x00' +\
                               b'\x00\x04' + bytes(ip_parts)
        m_msg = m_head + self.q_sec + m_record
        s.sendto(m_msg, self.addr)

    def query(self):
        # 向权威服务器查询
        global s, id_addr_dic, idg, id_map, name_server, debug_mode
        # ID转换
        q_id = next(idg) # 生成新ID
        query_data = q_id + self.data[2:]
        id_map[q_id] = self.id
        s.sendto(query_data, (name_server, 53))
        id_addr_dic[self.id] = self.addr

        # 调试模式
        if debug_mode == 2:
            print("sendto", (name_server, 53))
            print(data)
            print(self.id, "->", q_id)

        
def usage():
    print("\nUsage: python dns.py [-d | -r] [<dns-server>] [<db-file>]\n")

if __name__ == '__main__':
    print("DNSRELAY  Version 1.0")
    dns_dic = dict() # <域名-ip>字典
    id_addr_dic = {} # <id-ip端口>字典
    id_map = {} # ID转换映射表
    idg = id_gener() # ID生成器
    rc = record_count() # 序号生成器
    debug_mode = 0 # 调试模式
    name_server = '10.3.9.4'
    db_file = "dnsrelay.txt"

    # 获取调试模式
    if len(sys.argv) > 1:
        try:
            debug_opts, debug_args = getopt.getopt(sys.argv[1:],"dr")
            if len(debug_args) > 2 or len(debug_opts) > 1:
                raise getopt.GetoptError
            if debug_opts:
                if debug_opts[0][0] == '-d':
                    debug_mode = 1
                if debug_opts[0][0] == '-r':
                    debug_mode = 2
            if debug_args:
                name_server = debug_args[0]
            if len(debug_args) == 2:
                db_file = debug_args[1]
        except getopt.GetoptError:
            print("参数错误")
            usage()
            sys.exit()


    # 反馈信息
    usage()
    print("Name server", name_server)
    print("Debug level", debug_mode)
    # udp绑定
    print("Bind UDP port 53", end=' ')
    local_addr = ('', 53)
    #socket.setdefaulttimeout(20)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(local_addr)
    print("... OK!")
    
    crt_dns_dic(db_file)
 
    while True:
        try:
            # 接收一个数据
            data, addr = s.recvfrom(1024)  # 接收报文
            # 调试模式
            if debug_mode == 2:
                print("recvfrom", addr)
                print(data)

            if addr[1] != 53: # 查询报
                mm = Mes(data, addr)
                mm.get_ans()
            else: # 响应报
                q_id = data[0:2]
                r_id = 0
                if q_id in id_map:
                    r_id = id_map[q_id]
                    id_map.pop(q_id)
                if r_id in id_addr_dic:                   
                    res_data = r_id + data[2:]
                    s.sendto(res_data, id_addr_dic[r_id])
                    id_addr_dic.pop(r_id)
        except ConnectionResetError:
            #print('CRE')
            pass        


