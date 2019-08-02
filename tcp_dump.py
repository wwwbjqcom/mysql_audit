#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@author: Great God
'''

from scapy.all import *
import struct

def full_sessions(p):
    sess = "Other"
    if 'Ether' in p:
        if "IP" in p:
            if "TCP" in p:
                sess = str(sorted(["tcp",p['IP'].src,p['TCP'].sport,p['IP'].dst,p['TCP'].dport],key=str))
    return sess

a = sniff(filter="tcp and port 3306",count=100)
b = a.sessions(full_sessions)

session_status = {}

for k,v in b.items():
    #print(k,v)
    for ii in v:
        if 'Raw' in ii and ii['Raw'].load:
            _aa = ii['Raw'].load
            _s = 0
            packet_palyload = struct.unpack('B',_aa[2])[0] << 16 | struct.unpack('B',_aa[1])[0] << 8 |struct.unpack('B',_aa[0])[0]
            _s += 3
            packet_seq_id = struct.unpack('B',_aa[_s])[0]
            _s += 1
            packet_header = struct.unpack('B',_aa[_s])[0]
            _s += 1
            if packet_header == 0x03:
                session_status[k] = [ii['TCP'].time,_aa[_s:]]
            elif packet_header == 0xfe:
                # end_pos = _aa.find(b'\0', 6)
                # print(_aa[_s:end_pos])
                pass
            elif packet_header == 0xff:
                error_code = struct.unpack('<H', _aa[_s:_s + 2])
                _s += 2
                if k in session_status:
                    session_status[k].append(ii['TCP'].time)
                    session_status[k].append(_aa[_s:])
            elif packet_header in (0x00,0xfe):
                if packet_palyload > 7:
                    if k in session_status:
                        session_status[k].append(ii['TCP'].time)
                        session_status[k].append('ok')
                elif packet_palyload < 9:
                    print('error packet')
            #print(struct.unpack('B',_aa[2])[0] << 16 | struct.unpack('B',_aa[1])[0] << 8 |struct.unpack('B',_aa[0])[0],struct.unpack('B',_aa[3]),[_aa[4:]],ii['TCP'].time)

for key,value in session_status.items():
    if len(value) == 4:
        _time = value[2] - value[0]
        print('sql : {} execute time: {} execute status: {}'.format(value[1],_time,value[-1]))