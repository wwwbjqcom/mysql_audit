#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@author: xiao cai niao
'''
import pymysql,traceback

class db:
    def __init__(self,**kwargs):
        self.host = kwargs['host']
        self.port = kwargs['port']
        self.user = kwargs['user']
        self.passwd = kwargs['passwd']

    def get(self,host,port):
        try:
            self.conn = pymysql.connect(host=self.host,port=self.port,user=self.user,passwd=self.passwd,cursorclass=pymysql.cursors.DictCursor)
            self.cur = self.conn.cursor()
            sql = 'select `user`,`db` from information_schema.processlist where host=%s;'
            self.cur.execute(sql,'{}:{}'.format(host,port))
            result = self.cur.fetchall()
            if result:
                return result[0]['user'],result[0]['db']
            else:
                return None,None
        except:
            print(traceback.format_exc())
            return None,None

    def close(self):
        try:
            self.cur.close()
            self.conn.close()
        except:
            pass