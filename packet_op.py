#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@author: xiao cai niao
'''
from log import Logging
import socket,psutil,dpkt
from dpkt.compat import compat_ord
import time
from mysql_protocol import mysql_packet


class Op_packet:
    def __init__(self,**kwargs):
        self.kwargs = kwargs
        self.queue = kwargs['queue']
        self._type = kwargs['_type']
    def __get_netcard(self):
        '''获取IP地址'''
        info = psutil.net_if_addrs()
        for k, v in info.items():
            for item in v:
                if item[0] == 2 and not item[1] == '127.0.0.1' and ':' not in k:
                    netcard_info = item[1]
        return netcard_info

    def mac_addr(self,address):
        """Convert a MAC address to a readable/printable string

           Args:
               address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
           Returns:
               str: Printable/readable MAC address
        """
        return ':'.join('%02x' % compat_ord(b) for b in address)

    def inet_to_str(self,inet):
        """Convert inet object to a string

            Args:
                inet (inet struct): inet network address
            Returns:
                str: Printable/readable IP address
        """
        # First try ipv4 and then ipv6
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)

    def find_str(self,_str):
        str_list = []
        vv = 0
        while 1:
            v_i = _str.find(',', vv)
            if v_i == -1:
                str_list.append('?')
                break
            else:
                str_list.append('?')
                vv = v_i + 1
        return str_list

    def set_str(self,_str):
        str_list = _str.strip().split(' ')
        set_str = ''
        t = None
        _tmp_str = ''
        for set_value in str_list:
            if t:
                if set_value == str_list[-1]:
                    set_str += '?'
                else:
                    set_str += '?,'
                t = None
                continue
            if set_value == '=':
                set_str += _tmp_str + set_value
                t = True
                continue
            _tmp_str = set_value

        return set_str

    def sql_parser(self,sql):
        """Format sql
            Args:
                sql: Captured sql statement
            Returns:
                list: [sql,[values,]] If it is an insert statement, the returned data is empty.
        """
        sql = sql.strip().strip('\n')
        if sql.startswith('insert') or sql.startswith('INSERT'):
            k = sql.index('(')
            v = sql.index(')')
            v_str = tuple(self.find_str(sql[k:v + 1]))
            try:
                index = sql.index('values')
            except:
                index = sql.index('VALUES')

            return sql[:index + 6] + str(v_str), None


        elif sql.startswith('update') or sql.startswith('UPDATE'):
            try:
                set_index = sql.index('set')
            except:
                set_index = sql.index('SET')

            try:
                where_index = sql.index('where')
            except:
                try:
                    where_index = sql.index('WHERE')
                except:
                    where_index = None
            sql_start = sql[:set_index + 4]
            if where_index:
                sql_end = sql[where_index - 1:]
            else:
                sql_end = ''
            _set_str = self.set_str(sql[set_index + 4:where_index])
            return sql_start + _set_str + sql_end, None


        else:
            return sql, None

    def check_packet_type(self,response):
        respons_status = {
            'Text_Resultest': 1,
            'EOF_Packet': 1,
            'ERR_Packet': 0,
            'OK_Packet': 1,
            'Handshake_Packet': 1
        }

        return respons_status[response]

    def an_packet(self):
        _ip = self.__get_netcard()
        _mysql_packet_op = mysql_packet(**dict({'_type':self._type},**{'_ip':_ip}))
        session_status = {}
        while 1:
            if not self.queue.empty():
                buf,_cur_time = self.queue.get()
                eth = dpkt.ethernet.Ethernet(buf)

                if not isinstance(eth.data, dpkt.ip.IP):
                    Logging(msg='Non IP Packet type not supported %s\n' % eth.data.__class__.__name__,level='error')
                    continue

                ip = eth.data
                tcp = dpkt.tcp.TCP(str(ip.data))
                if (tcp.dport == self.kwargs['port'] or tcp.sport == self.kwargs['port']) and len(tcp.data) > 0 \
                        and 'interface' not in tcp.data and 'tbl_sessions' not in tcp.data:
                    if len(tcp.data) > 5:
                        session, packet_response, client_packet_text, packet_header, packet_seq_id,response_type,response_status=_mysql_packet_op.Unpacking(
                                                                                data=tcp.data,srchost=self.inet_to_str(ip.src),
                                                        srcport=tcp.sport,dsthost=self.inet_to_str(ip.dst),dstport=tcp.dport)
                    else:
                        continue

                    if client_packet_text:
                        session_status[session] = {'start_time':_cur_time,'request_text':client_packet_text,
                                                   'request_header':packet_header,'seq_id':packet_seq_id,'response_type':response_type}
                        if packet_header == 0x16:
                            session_status[session]['com_pre'] = True
                        elif packet_header == 0x17 and 'com_pre' in session_status[session]:
                            del session_status[session]['com_pre']
                    elif packet_response:
                        if session in session_status and packet_response in session_status[session]['response_type']:
                            if packet_seq_id - 1 == session_status[session]['seq_id'] and 'com_pre' not in session_status[session]:
                                session_status[session]['end_time'] = _cur_time
                                session_status[session]['status'] = self.check_packet_type(packet_response)
                                session_status[session]['response_status'] = response_status

                del_session = []
                for session in session_status:
                    if 'status' in session_status[session]:
                        execute_time = float('%.5f' % (session_status[session]['end_time'] - session_status[session]['start_time']))
                        if session_status[session]['request_header'] == 0x03:
                            sql, values = self.sql_parser(session_status[session]['request_text'])
                        else:
                            sql, values = session_status[session]['request_text'],None
                        _session = eval(session)

                        Logging(msg=
                            'source_host: {} source_port: {} destination_host: {} destination_port: {} sql: {} values: {} '
                            'execute_time:{}  status:{}'.format(_session[0], _session[1], _session[2],_session[3],
                                                                sql, values,
                                                                execute_time,
                                                                session_status[session]['response_status']),level='info')
                        del_session.append(session)

                for session in del_session:
                    del session_status[session]

            else:
                time.sleep(0.01)