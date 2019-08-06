该小工具通过实时获取数据包的方式，分析并解析出请求的sql语句、执行用户、执行状态和执行时间，insert和update语句对数据做了格式化操作，update语句的where条件保留了数据，select、delete语句未做格式化，可以放于应用端、中间件层、mysql服务器上，在不影响mysql本身性能的情况下获取所有语句的基本情况，可做审计作用，如果是新建连接会从数据包中解析出用户名、如果是长连接且提供了mysql连接使用的用户名密码会远程连接数据库获取连接所用的用户名，假如需从数据库获取用户，该工具获取的数据流来源ip信息应该是直连数据库或未被中间件改变，因为使用数据包解析出的ip作为连接数据库或查询的依据，如果不能直接获取可以先启动小工具再启动应用或中间件，这样可以解包获取用户名，兼容py2、py3：

需求的包：
    dpkt、psutil、pypacp、pymysql

执行方式：
    python tcp_audit.py -h 可以获取参数介绍

示例：
    比如我在中间件层对后面3306端口的数据流进行监听： python tcp_audit.py -e eth0 -p 3306 -t src -u username -P password
    如果是对本地端口进行监听，比如我们中间件层端口为6001： python tcp_audit.py -e eth0 -p 6001 -t des （这里未提供用户名密码，因为中间件改变了来源信息，而我监听的是应用到中间件这层的数据流，所以不能直接获取链接所使用的用户，只能使用默认的解包获取）

获取内容打印如下：
    2019-08-06 08:52:22,984  INFO  log.py : INFO  source_host: 10.1.11.59 source_port: 59272 destination_host: 10.1.1.46 destination_port: 3306 user_name: test01 sql: INSERT INTO proxy_heart_beat.tb_heartbeat (p_id, p_ts) VALUES('?', '?') values: None execute_time:0.0001  status:#42000INSERT, UPDATE command denied to user 'test01'@'10.1.11.59' for table 'tb_heartbeat'
    
日志没10分钟切割一次，保留一个小时的，如果有需要保留更长或者更改切割时间，可以修改log.py中的参数
