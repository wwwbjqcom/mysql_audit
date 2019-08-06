# -*- coding: utf-8 -*-
'''
@Author  : xiao cai niao
'''

import pcap
import sys
import getopt
import time
from lib.packet_op import Op_packet
from lib.log import Logging
from multiprocessing import Process
from multiprocessing import Queue

my_queue = Queue(1024)



def print_packets(**kwargs):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """

    t = ThreadDump(**dict(kwargs,**{'queue':my_queue}))
    t.start()

    _pcap = pcap.pcap(name=kwargs['eth'], promisc=True, immediate=True, timeout_ms=5000)
    _pcap.setfilter("tcp port {}".format(kwargs['port']))

    _logging = Logging()
    for timestamp, buf in _pcap:
        if sys.version_info < (3, 0):
            _time = time.time()
        else:
            _time = timestamp
        if append_data((buf,_time)):
            pass
        else:
            _logging.error('queue is full!!!!!!!')
            sys.exit()


def append_data(data):
    for i in range(100):
        if my_queue.full():
            time.sleep(1)
            continue
        my_queue.put(data)
        return True
    else:
        return False








class ThreadDump(Process):
    def __init__(self,**kwargs):
        super(ThreadDump,self).__init__()
        self.kwargs = kwargs
    def run(self):
        Op_packet(**self.kwargs).an_packet()


def Usage():
    __usage__ = """
    	Usage:
    	Options:
      		-h [--help] : print help message
      		-p [--port] : tcp port 
      		-e [--eth]  : network card
      		-t [--type] : define whether the local address is the sender or the receiver [src/des]
      		-u [--user] : remote mysql node username
      		-P [--passwd] : mysql password
    	    """
    print(__usage__)


def main(argv):
    _argv = {}
    try:
        opts, args = getopt.getopt(argv[1:], 'hp:e:t:u:P:',
                                   ['help', 'port=', 'eth=','type=','user=','passwd='])
    except getopt.GetoptError as err:
        print(str(err))
        Usage()
        sys.exit(2)
    for o, a in opts:
        if o in ('-h', '--help'):
            Usage()
            sys.exit(1)
        elif o in ('-p', '--port'):
            _argv['port'] = int(a)
        elif o in ('-e','--eth'):
            _argv['eth'] = a
        elif o in ('-t','--type'):
            _argv['_type'] = a
        elif o in ('-u','--user'):
            _argv['user'] = a
        elif o in ('-P','--passwd'):
            _argv['passwd'] = a
        else:
            print('unhandled option')
            Usage()
            sys.exit(3)

    print_packets(**_argv)


if __name__ == "__main__":
    main(sys.argv)



