from scapy.all import ARP, Ether, srp
import threading
from csv import DictReader
from socket import getfqdn

_print = print
mutex = threading.Lock()
# 定义新的print函数
def print(text, *args, **kw):
    '''
    使输出有序进行，不出现多线程同一时间输出导致错乱的问题。
    '''
    with mutex:
        _print(text, *args, **kw)

with open(r'./table/oui.csv','r',encoding='utf-8') as f:
    f_csv = DictReader(f)
    mac_list = [row for row in f_csv]

mac_add = []
for i in mac_list:
    mac_add.append(i["Assignment"])

def get_info(mac):
    try:
        return mac_list[mac_add.index(mac[:6])]['Organization Name']
    except:
        return 'unknown'


tip = ARP().psrc
tip = tip[:(len(tip)-tip[::1].find('.'))]

def arp_scan(ip):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    try:
        res = srp(pkt, timeout=10, verbose=0)
        return res[0][0].answer.src
    except:
        pass

def data_form(ip):
    mac = arp_scan(ip)
    if mac:
        info = get_info(mac.replace(':','').upper())
        hostname = getfqdn(ip)
        data = {'ip':ip, 'mac':mac, 'hostname':hostname, 'Organization Name':info}
        print("{:<15}".format(data['ip']),'|',"{:<17}".format(data['mac']),'|',"{:<25}".format(data['hostname']),'|',data['Organization Name'],end='\n')
    else:
        pass

def run():
    print("{:<17}".format('IP'),"{:<19}".format("MAC"),"{:<27}".format("HOSTNAME"),'ORGANIZATION','\n——————————————————————————————————————————————————————————————————————————————')
    thread_list = []
    for i in range(1, 256):
        ip = tip + str(i)
        thread_list.append(threading.Thread(target=data_form, args=(ip,)))
    for i in thread_list:
        i.start()
    for i in thread_list:
        i.join()

if __name__=='__main__':
    arp_scan('192.168.31.42')
    print("")
    '''thread_list = []
    for i in range(1,256):
        ip = tip + str(i)
        thread_list.append(threading.Thread(target=data_form,args=(ip,)))
    for i in thread_list:
        i.start()
    for i in thread_list:
        i.join()'''