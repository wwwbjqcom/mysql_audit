#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@author: xiao cai niao
'''
import struct,sys

class mysql_packet(object):
    def __init__(self, **kwargs):
        self.data = None
        self.offset = 0
        self._ip = kwargs['_ip']
        self._type = kwargs['_type']    #src : This machine is the initiator  des: This machine is the receiver

        self.client_packet_type = {
            0x03: self.COM_QUERY,
            0x01: self.COM_QUIT,
            0x02: self.COM_INIT_DB,
            0x04: self.COM_FIELD_LIST,
            0x07: self.COM_PREFRESH,
            0x08: self.COM_STATISTICS,
            0x0A: self.COM_PROCESS_INFO,
            0x0C: self.COM_PROCESS_KILL,
            0x0D: self.COM_DEBUG,
            0x0E: self.COM_PING,
            0x11: self.COM_CHANGE_USER,
            0x1F: self.COM_RESET_CONNECTION,
            0x1A: self.COM_SET_OPTION,
            0x16: self.COM_STMT_PREPARE,
            0x17: self.COM_STMT_EXECUTE,
            0x19: self.COM_STMT_CLOSE,
            0x1A: self.COM_STMT_RESET,
            0x18: self.COM_STMT_SEND_LONG_DATA
        }

    def COM_QUERY(self):
        """
        Type	    Name	Description
        int<1>	    command	0x03: COM_QUERY
        string<EOF>	query	the text of the SQL query to execute
        """
        return self.data[self.offset:].decode("utf8","ignore"),['OK_Packet','ERR_Packet','Text_Resultest']

    def COM_QUIT(self):
        """
        Type	Name	    Description
        int<1>	command	    0x01: COM_QUIT

        Server closes the connection or returns ERR_Packet.
        """
        return 'COM_QUIT',[]

    def COM_INIT_DB(self):
        """
        Type	    Name	    Description
        int<1>	    command	    0x02: COM_INIT_DB
        string<EOF>	schema name	name of the schema to change to

        server return:
            OK_Packet on success
            ERR_Packet on error
        """
        return self.data[self.offset:].decode("utf8","ignore"),['OK_Packet','ERR_Packet']

    def COM_FIELD_LIST(self):
        """
        As of MySQL 5.7.11, COM_FIELD_LIST is deprecated and will be removed in a future version of MySQL.
        Instead, use COM_QUERY to execute a SHOW COLUMNS statement

        Type	    Name	    Description
        int<1>	    command	    0x04: COM_FIELD_LIST
        string<NUL>	table	    the name of the table to return column information for (in the current database for the connection)
        string<EOF>	wildcard	field wildcard
        """
        return self.data[self.offset:].decode("utf8","ignore"),[]

    def COM_PREFRESH(self):
        """
        As of MySQL 5.7.11, COM_REFRESH is deprecated and will be removed in a future version of MySQL. Instead,
        use COM_QUERY to execute a FLUSH statement

        Type	Name	    Description
        int<1>	command	    0x07: COM_REFRESH
        int<1>	sub_command	A bitmask of sub-systems to refresh. A combination of the first 8 bits of COM_REFRESH Flags

        server return:
            ERR_Packet or OK_Packet
        """
        return 'COM_PREFRESH',['OK_Packet','ERR_Packet']

    def COM_STATISTICS(self):
        """
        Get a human readable string of some internal status vars

        Type	Name	Description
        int<1>	command	0x08: COM_STATISTICS

        server return:
            elther a string<EOF>
            https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_strings.html#sect_protocol_basic_dt_string_eof
        """
        return 'COM_STATISTICS',[]

    def COM_PROCESS_INFO(self):
        """
        As of 5.7.11 COM_PROCESS_INFO is deprecated in favor of COM_QUERY with SHOW PROCESSLIST

        Type	Name	Description
        int<1>	command	0x0A: COM_PROCESS_INFO

        server return:
            Text Resultset or a ERR_Packet
        """
        return 'COM_PROCESS_INFO',['ERR_Packet','Text_Resultest']

    def COM_PROCESS_KILL(self):
        """
        As of MySQL 5.7.11, COM_PROCESS_KILL is deprecated and will be removed in a future version of MySQL. Instead,
        use COM_QUERY and a KILL command

        Type	Name	        Description
        int<1>	command	        0x0C: COM_PROCESS_KILL
        int<4>	connection_id	The connection to kill

        server return:
            ERR_Packet or OK_Packet
        """

        return 'COM_PROCESS_KILL',['OK_Packet','ERR_Packet']

    def COM_DEBUG(self):
        """
        Dump debug info to server's stdout

        COM_DEBUG triggers a dump on internal debug info to stdout of the mysql-server.

        The SUPER_ACL privilege is required for this operation

        Type	Name	Description
        int<1>	command	0x0D: COM_DEBUG

        server return:
            ERR_Packet or OK_Packet
        """

        return 'COM_DEBUG',['OK_Packet','ERR_Packet']

    def COM_PING(self):
        """
        Check if the server is alive

        Type	Name	Description
        int<1>	command	0x0E: COM_PING

        server return:
            OK_Packet
        """

        return 'COM_PING',['OK_Packet']

    def COM_CHANGE_USER(self):
        """
        Changes the user of the current connection.

        Also and resets the following connection state:

        user variables
        temporary tables
        prepared statements
        ... and others
        It is going through the same states as the Initial Handshake

        Type	Name	    Description
        int<1>	command	    0x11: COM_CHANGE_USER
        .........................................
        https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_change_user.html

        server return:
            Protocol::AuthSwitchRequest: or ERR_Packet
        """

        return 'COM_CHANGE_USER',['ERR_Packet','Handshake_Packet']

    def COM_RESET_CONNECTION(self):
        """
        Resets the session state

        A more lightweightt version of COM_CHANGE_USER that does about the same to clean up the session state, but:

        it does not re-authenticate (and do the extra client/server exchange for that)
        it does not close the connection


        Type	Name	    Description
        int<1>	command	    0x1F: COM_RESET_CONNECTION

        server restun:
            OK_Packet
        """

        return 'COM_RESET_CONNECTION',['OK_Packet']

    def COM_SET_OPTION(self):
        """
        Sets options for the current connection

        COM_SET_OPTION enables and disables server capabilities for the current connection.


        Type	Name	            Description
        int<1>	status	            [0x1A] COM_SET_OPTION
        int<2>	option_operation	One of enum_mysql_set_option

        server return:
            OK_Packet on success, ERR_Packet otherwise.
        """
        return 'COM_SET_OPTION',['OK_Packet','ERR_Packet']

    def COM_STMT_PREPARE(self):
        """
        Creates a prepared statement for the passed query string

        Type	    Name	        Description
        int<1>	    command	        0x16: COM_STMT_PREPARE
        string<EOF>	query	        The query to prepare

        server return:
            COM_STMT_PREPARE_OK on success, ERR_Packet otherwise
        """
        return self.data[self.offset:].decode("utf8","ignore"),['OK_Packet','ERR_Packet']

    def COM_STMT_EXECUTE(self):
        """
        COM_STMT_EXECUTE asks the server to execute a prepared statement as identified by statement_id

        Type	Name	        Description
        int<1>	status	        [0x17] COM_STMT_EXECUTE
        int<4>	statement_id	ID of the prepared statement to execute
        int<1>	flags	        Flags. See enum_cursor_type
        ...................................................
        see: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html

        server return:
            COM_STMT_EXECUTE Response
            see: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute_response.html

        :returns
            statement_id
        """

        return 'COM_STMT_EXECUTE',[]

    def COM_STMT_FETCH(self):
        """
        Fetches the requested amount of rows from a resultset produced by COM_STMT_EXECUTE

        Type	Name	        Description
        int<1>	status	        0x18
        int<4>	statement_id	ID of the prepared statement to close
        int<4>	num_rows	    max number of rows to return

        server return:
            Multi-Resultset : https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase_sp.html#sect_protocol_command_phase_sp_multi_resultset
            ERR_Packet

        :returns
            statement_id
        """

        return 'COM_STMT_FETCH',['ERR_Packet','Text_Resultest']


    def COM_STMT_CLOSE(self):
        """
        COM_STMT_CLOSE deallocates a prepared statement.

        No response packet is sent back to the client.

        Type	Name	        Description
        int<1>	status	        [0x19] COM_STMT_CLOSE
        int<4>	statement_id	ID of the prepared statement to close
        """
        return 'COM_STMT_CLOSE',[]

    def COM_STMT_RESET(self):
        """
        COM_STMT_RESET resets the data of a prepared statement which was accumulated with COM_STMT_SEND_LONG_DATA commands
        and closes the cursor if it was opened with COM_STMT_EXECUTE.

        The server will send a OK_Packet if the statement could be reset, a ERR_Packet if not.

        server return:
            OK_Packet or a ERR_Packet

        Type	Name	        Description
        int<1>	status	        [0x1A] COM_STMT_RESET
        int<4>	statement_id	ID of the prepared statement to reset
        """

        return 'COM_STMT_RESET',['OK_Packet','ERR_Packet']

    def COM_STMT_SEND_LONG_DATA(self):
        """
        Sends the data for a parameter.

        Repeating to send it, appends the data to the parameter.

        No response is sent back to the client

        Type	    Name	        Description
        int<1>	    status	        [0x18] COM_STMT_SEND_LONG_DATA
        int<4>	    statement_id	ID of the statement
        int<2>	    param_id	    The parameter to supply data to
        binary<var>	data	        The actual payload to send

        """

        return 'COM_STMT_SEND_LONG_DATA',[]

    def Connection_Packets(self, capability_flags=None):
        """
        see :
            https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html
        """
        client_plugin_auth_lenenc_client_data = 1<<21
        secure_connection = 1<<15
        client_connect_with_db = 9
        db_name = ''
        self.offset = 36
        _s_end = self.data.find(b'\0', self.offset)
        user_name = self.data[self.offset:_s_end].decode("utf8","ignore")
        self.offset = _s_end + 1;

        if capability_flags & client_plugin_auth_lenenc_client_data or capability_flags & secure_connection:
            passwd_len = struct.unpack('B',self.data[self.offset:self.offset+1])[0]
            self.offset += passwd_len + 1
        else:
            _s_end = self.data.find(b'\0', self.offset)
            self.offset = _s_end + 1;

        if capability_flags & client_connect_with_db:
            _s_end = self.data.find(b'\0', self.offset)
            db_name = self.data[self.offset:_s_end].decode("utf8","ignore")
        return user_name,db_name,['Handshake_Packet']

    def Handshake_Packet(self):
        """
        Initial Handshake Packet

        When the client connects to the server the server sends a handshake packet to the client.
        Depending on the server version and configuration options different variants of the initial packet are sent

        Protocol::HandshakeV9:  0x09
        Protocol::HandshakeV10: 0x10
        """
        _s_end = self.data.find(b'\0', self.offset)
        server_version = self.data[self.offset:_s_end].decode("utf8","ignore")
        self.offset  = _s_end + 1 + 4 + 8 + 1
        capability_flags_1 = struct.unpack('H', self.data[self.offset:self.offset + 2])[0]
        self.offset += 5
        capability_flags_2 = struct.unpack('H', self.data[self.offset:self.offset + 2])[0]
        capability_flags = capability_flags_2 << 16 | capability_flags_1

        return server_version,'create connection',capability_flags

    def OK_Packet(self):
        """
        An OK packet is sent from the server to the client to signal successful completion of a command.

        As of MySQL 5.7.5, OK packes are also used to indicate EOF, and EOF packets are deprecated

        Type	        Name	            Description
        int<1>	        header	            0x00 or 0xFE the OK packet header
        int<lenenc>	    affected_rows	    affected rows
        int<lenenc>	    last_insert_id	    last insert-id
        ..................................................
        see: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html

        :return:
        """

        return 'OK_Packet','OK',None

    def ERR_Packet(self):
        """
        This packet signals that an error occurred.

        It contains a SQL state value if CLIENT_PROTOCOL_41 is enabled

        Type	    Name	            Description
        int<1>	    header	            0xFF ERR packet header
        int<2>	    error_code	        error-code
        if capabilities & CLIENT_PROTOCOL_41 {
        string[1]	sql_state_marker	# marker of the SQL state
        string[5]	sql_state	        SQL state
        }
        string<EOF>	error_message	    human readable error message

        see:  https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
        """
        return 'ERR_Packet',self.data[self.offset+2:].decode("utf8","ignore"),None

    def EOF_Packet(self):
        """
        If CLIENT_PROTOCOL_41 is enabled, the EOF packet contains a warning count and status flags.

        In the MySQL client/server protocol, the EOF_Packet and OK_Packet packets serve the same purpose,
        to mark the end of a query execution result. Due to changes in MySQL 5.7 in the OK_Packet packets (such as session state tracking),
        and to avoid repeating the changes in the EOF_Packet packet, the OK_Packet is deprecated as of MySQL 5.7.5

        Type	Name	Description
        int<1>	header	0xFE EOF packet header
        ...........................
        """
        return 'EOF_Packet','EOF',None

    def Text_Resultest(self):
        """
        A Text Resultset is a possible COM_QUERY Response.

        It is made up of 2 parts:

        the column definitions (a.k.a. the metadata)
        the actual rows

        see: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html

        """
        return 'Text_Resultest','Result',None

    def check_(self,packet_header,response_header):
        """

        :param packet_header:
        :return:
        """


    def check_server_response(self,packet_header):
        if self.packet_palyload == 1:
            return self.Text_Resultest()
        elif packet_header == 0x00 and self.packet_palyload >= 7:
            return self.OK_Packet()
        elif packet_header == 0xfe and self.packet_palyload <= 9:
            return self.EOF_Packet()
        elif packet_header == 0xff:
            return self.ERR_Packet()
        elif packet_header in (0x09,0x0a):
            return self.Handshake_Packet()
        else:
            return self.Text_Resultest()

    def Unpacking(self,data,srchost,srcport,dsthost,dstport,all_session_users):
        """
        unpack packet
        :return:
        """
        self.data = data
        session = None
        packet_response = None
        client_packet_text = None
        response_status = None
        response_type = []
        db_name = None
        capability_flags = None

        self.unpacke_value()
        if self._type == 'src':
            if srchost == self._ip:
                '''client packet'''
                session = str([srchost,srcport,dsthost,dstport])
                if session in all_session_users and all_session_users[session]['pre'] and self.packet_seq_id and self.packet_seq_id-1==all_session_users[session]['seq_id']:
                    client_packet_text, db_name, response_type = self.Connection_Packets(all_session_users[session]['capability_flags'])
                elif self.packet_header in self.client_packet_type:
                    client_packet_text,response_type = self.client_packet_type[self.packet_header]()
            else:
                '''server response'''
                session = str([dsthost, dstport, srchost, srcport])
                if any([self.packet_palyload,self.packet_seq_id,self.packet_header]):
                    packet_response,response_status, capability_flags = self.check_server_response(self.packet_header)

        elif self._type == 'des':
            if srchost == self._ip:
                '''server response'''
                session = str([dsthost, dstport, srchost, srcport])
                if any([self.packet_palyload,self.packet_seq_id,self.packet_header]):
                    packet_response,response_status, capability_flags = self.check_server_response(self.packet_header)
            else:
                '''client packet'''
                session = str([srchost, srcport,dsthost, dstport])
                if session in all_session_users and all_session_users[session]['pre'] and self.packet_seq_id and self.packet_seq_id-1==all_session_users[session]['seq_id']:
                    client_packet_text, db_name, response_type = self.Connection_Packets(all_session_users[session]['capability_flags'])
                elif self.packet_header in self.client_packet_type:
                    client_packet_text,response_type = self.client_packet_type[self.packet_header]()

        return session,packet_response,client_packet_text,self.packet_header,self.packet_seq_id,response_type,response_status,db_name,capability_flags


    def unpacke_value(self):
        if sys.version_info < (3, 0):
            try:
                self.offset = 0
                self.packet_palyload = struct.unpack('B',self.data[2])[0] << 16 | \
                                       struct.unpack('B',self.data[1])[0] << 8 | \
                                       struct.unpack('B',self.data[0])[0]
                self.offset += 3
                self.packet_seq_id = struct.unpack('B',self.data[self.offset])[0]
                self.offset += 1
                self.packet_header = struct.unpack('B',self.data[self.offset])[0]
                self.offset += 1
            except:
                self.packet_palyload, self.packet_seq_id, self.packet_header = None, None, None
        else:
            try:
                self.offset = 0
                self.packet_palyload = self.data[2] << 16 | self.data[1] << 8 | self.data[0]
                self.offset += 3
                self.packet_seq_id = self.data[self.offset]
                self.offset += 1
                self.packet_header = self.data[self.offset]
                self.offset += 1
            except:
                self.packet_palyload, self.packet_seq_id, self.packet_header = None, None, None