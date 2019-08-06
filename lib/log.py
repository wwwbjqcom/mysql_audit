# -*- encoding: utf-8 -*-
'''
@author: xiao cai niao
'''
import logging
import logging.handlers


class Logging:
    def __init__(self):
        self.logger = logging.getLogger("tcp_audit")
        self.logger.setLevel(logging.DEBUG)
        self.rf_handler = logging.handlers.TimedRotatingFileHandler(filename="log/tcp_audit.log", when='M', interval=10, \
                                                                    backupCount=6)
        self.rf_handler.setFormatter(
            logging.Formatter("%(asctime)s  %(levelname)s  %(filename)s : %(levelname)s  %(message)s"))

        self.logger.addHandler(self.rf_handler)


    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def debug(self, msg):
        self.logger.debug(msg)

    def close(self):
        self.logger.removeHandler(self.rf_handler)
