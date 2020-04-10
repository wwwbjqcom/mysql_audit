#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@author: xiao cai niao
'''
from lib.log import Logging
import socket,psutil,dpkt
from dpkt.compat import compat_ord
import time,threading
from lib.mysql_protocol import mysql_packet
from lib.db import db
import json

class Op_packet:
    def __init__(self,**kwargs):
        self.kwargs = kwargs
        self.queue = kwargs['queue']
        self._type = kwargs['_type']

        self.mysql_user = kwargs['user'] if 'user' in kwargs else None
        self.mysql_passwd = kwargs['passwd'] if 'passwd' in kwargs else None
        if self.mysql_user:
            if self.mysql_passwd:
                pass
            else:
                print('Mysql connection information needs to be set at the same time')
                import sys
                sys.exit()

        self.all_session_users = {}
        self.get_user_list = {}

    def __get_netcard(self):
        '''get ip address'''
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

    def conn_maintain(self):
        while 1:
            if self.get_user_list:
                __get_list = self.get_user_list.copy()
                for session in __get_list:
                    self.get_user_info(*__get_list[session])
                    del self.get_user_list[session]

            _idle_timeout_session = []
            if self.all_session_users:
                __all_session_users = self.all_session_users.copy()
                for session in __all_session_users:
                    _cur_time = time.time()
                    if int(_cur_time - __all_session_users[session]['date']) > 300:
                        _idle_timeout_session.append(session)

            for session in _idle_timeout_session:
                del self.all_session_users[session]

            time.sleep(0.1)

    def sql_parser(self,sql):
        """Format sql
            Args:
                sql: Captured sql statement
            Returns:
                list: [sql,[values,]] If it is an insert statement, the returned data is empty.
        """
        sql = sql.strip('\n').strip()
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

    def create_conn(self,session,client_packet_text,packet_seq_id,type,response_type,response_status):
        """

        :param session:
        :param client_packet_text:
        :param packet_seq_id:
        :param type:
        :param response_type:
        :param response_status:
        :return:
        """
        if self.all_session_users[session]['status']:
            pass
        else:
            if type == 'client':
                if session in self.all_session_users and self.all_session_users[session]['pre']:
                    if packet_seq_id - 1 == self.all_session_users[session]['seq_id']:
                        self.all_session_users[session]['pre'] = False
                        self.all_session_users[session]['user'] = client_packet_text
                        self.all_session_users[session]['seq_id'] = packet_seq_id
                    else:
                        del  self.all_session_users[session]
                    # self.create_conn(session,client_packet_text)
                elif session in self.all_session_users and not self.all_session_users[session]['status']:
                    if packet_seq_id - 1 == self.all_session_users[session]['seq_id']:
                        self.all_session_users[session]['seq_id'] = packet_seq_id
                    else:
                        del self.all_session_users[session]
            elif type == 'response':
                if session in self.all_session_users and response_type in ('OK_Packet','ERR_Packet'):
                    if packet_seq_id - 1 == self.all_session_users[session]['seq_id']:
                        self.all_session_users[session]['status'] = True
                        self.all_session_users[session]['date'] = time.time()
                        _session = eval(session)
                        jsons = {'source_host': _session[0], 'source_port': _session[1],
                                 'destination_host': _session[2], 'destination_port': _session[3],
                                 'user_name': self.all_session_users[session]['user'], 'sql': 'create connection', 'values': None,
                                 'execute_time': None,
                                 'status': response_status, 'time': time.time()}
                        self._logging.info(msg=json.dumps(jsons))
                        # self._logging.info(msg=
                        #               'source_host: {} source_port: {} destination_host: {} destination_port: {} user_name: {} sql: {} values: {} '
                        #               'execute_time:{}  status:{}'.format(_session[0], _session[1], _session[2],
                        #                                                   _session[3],
                        #                                                   self.all_session_users[session]['user'],
                        #                                                   'create connection', None,
                        #                                                   None,response_status))
                        if response_type == 'ERR_Packet':
                            del self.all_session_users[session]
                    else:
                        del self.all_session_users[session]

                elif session in self.all_session_users:
                    if packet_seq_id - 1 == self.all_session_users[session]['seq_id']:
                        self.all_session_users[session]['seq_id'] = packet_seq_id
                    else:
                        del self.all_session_users[session]

    def get_user_info(self,host,port,mysql_host,mysql_port,session):
        """select user_name from mysql instance"""
        if self.mysql_user:
            _kwargs = {'host':mysql_host,'port':mysql_port,'user':self.mysql_user,'passwd':self.mysql_passwd}
            dd = db(**_kwargs)
            user_name = dd.get(host,port)
            if user_name:
                self.all_session_users[session] = {'status':True,'user':user_name,'pre':False,'date':time.time()}
            dd.close()
            return user_name
        else:
            return None




    def an_packet(self):
        _ip = self.__get_netcard()
        _mysql_packet_op = mysql_packet(**dict({'_type':self._type},**{'_ip':_ip}))
        session_status = {}
        self._logging = Logging()

        t = threading.Thread(target=self.conn_maintain,args=())
        t.start()

        while 1:
            if not self.queue.empty():
                buf,_cur_time = self.queue.get()
                eth = dpkt.ethernet.Ethernet(buf)

                if not isinstance(eth.data, dpkt.ip.IP):
                    self._logging.error(msg='Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
                    continue

                ip = eth.data

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    src_host,dst_host = self.inet_to_str(ip.src),self.inet_to_str(ip.dst)
                    session, packet_response, client_packet_text, packet_header, packet_seq_id,response_type,response_status=_mysql_packet_op.Unpacking(
                                                                                data=tcp.data,srchost=src_host,
                                                        srcport=tcp.sport,dsthost=dst_host,dstport=tcp.dport,
                        all_session_users=self.all_session_users)

                    if packet_response and packet_response in ('COM_PROCESS_KILL', 'COM_QUIT'):
                        """close connection"""
                        if session in self.all_session_users:
                            del self.all_session_users[session]


                    if client_packet_text:
                        if session in self.all_session_users:
                            self.create_conn(session,client_packet_text,packet_seq_id,'client',response_type,response_status)

                        if packet_header == 0x16:
                            session_status[session] = {'start_time': _cur_time, 'request_text': client_packet_text,
                                                       'request_header': packet_header, 'seq_id': packet_seq_id,
                                                       'response_type': response_type,'com_pre':True}

                        elif packet_header == 0x17 and session in session_status and 'com_pre' in session_status[session]:
                            del session_status[session]['com_pre']
                            continue

                        elif packet_header in (0x01, 0x18):
                            session_status[session] = {'start_time': _cur_time, 'request_text': client_packet_text,
                                                       'request_header': packet_header, 'seq_id': packet_seq_id,
                                                       'response_type': response_type,'end_time':_cur_time,
                                                       'status':1,'response_status':None}
                        elif packet_header == 0x19:
                            continue
                        else:
                            session_status[session] = {'start_time': _cur_time, 'request_text': client_packet_text,
                                                       'request_header': packet_header, 'seq_id': packet_seq_id,
                                                       'response_type': response_type}

                        if session in self.all_session_users and self.all_session_users[session]['status']:
                            session_status[session]['user_name'] = self.all_session_users[session]['user']
                            self.all_session_users[session]['date'] = _cur_time
                        elif session not in self.all_session_users:
                            # session_status[session]['user_name'] = self.get_user_info(host=src_host,port=tcp.sport,
                            #                                                           mysql_host=dst_host,
                            #                                                           mysql_port=tcp.dport,
                            #                                                           session=session)
                            session_status[session]['user_name'] = None
                            if session not in self.get_user_list and packet_header not in (0x01, 0x19, 0x18) and any([self.mysql_user,self.mysql_passwd]):
                                self.get_user_list[session]=[src_host,tcp.sport,dst_host,tcp.dport,session]


                    elif packet_response:
                        if packet_header and packet_header in (0x09, 0x0a):
                            """connection"""
                            self.all_session_users[session] = {'pre': True, 'user': None,
                                                               'server_version': packet_response,
                                                               'seq_id': packet_seq_id, 'status': False,'date':_cur_time}
                            continue
                        if session in self.all_session_users:
                            self.create_conn(session,client_packet_text,packet_seq_id,'response',packet_response,response_status)

                        if session in session_status :
                            if packet_response in session_status[session]['response_type']:
                                if packet_seq_id - 1 == session_status[session]['seq_id'] and 'com_pre' not in session_status[session]:
                                    session_status[session]['end_time'] = _cur_time
                                    session_status[session]['status'] = self.check_packet_type(packet_response)
                                    session_status[session]['response_status'] = response_status
                                elif packet_seq_id - 1 != session_status[session]['seq_id']:
                                    del session_status[session]
                            else:
                                del session_status[session]

                    elif session in self.all_session_users and not self.all_session_users[session]['status'] and packet_seq_id:
                        if packet_seq_id - 1 == self.all_session_users[session]['seq_id']:
                            self.all_session_users[session]['seq_id'] = packet_seq_id
                    else:
                        if session in session_status:
                            del session_status[session]

                del_session = []
                for session in session_status:
                    if 'status' in session_status[session]:
                        execute_time = float('%.4f' % (session_status[session]['end_time'] - session_status[session]['start_time']))
                        if session_status[session]['request_header'] == 0x03:
                            sql, values = self.sql_parser(session_status[session]['request_text'])
                        else:
                            sql, values = session_status[session]['request_text'],None
                        _session = eval(session)
                        try:
                            jsons = {'source_host':_session[0],'source_port':_session[1],'destination_host':_session[2],'destination_port':_session[3],
                                     'user_name':session_status[session]['user_name'],'sql':sql, 'values':values,'execute_time':execute_time,
                                     'status':session_status[session]['response_status'], 'time':_cur_time}
                            self._logging.info(msg=json.dumps(jsons))
                            # self._logging.info(msg=
                            #     'source_host: {} source_port: {} destination_host: {} destination_port: {} user_name: {} sql: {} values: {} '
                            #     'execute_time:{}  status:{}'.format(_session[0], _session[1], _session[2],_session[3],
                            #                                         session_status[session]['user_name'],
                            #                                         sql, values,
                            #                                         execute_time,
                            #                                         session_status[session]['response_status']))
                        except:
                            pass
                        del_session.append(session)

                for session in del_session:
                    del session_status[session]

            else:
                time.sleep(0.01)