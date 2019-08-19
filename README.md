# mysql_audit

该小工具通过实时获取数据包的方式，分析并解析出请求的sql语句、执行用户、执行状态和执行时间，insert和update语句对数据做了格式化操作，update语句的where条件保留了数据，select、delete语句未做格式化，可以放于应用端、中间件层、mysql服务器上，在不影响mysql本身性能的情况下获取所有语句的基本情况，可做审计作用，兼容py2、py3，mysql5.7/8.0测试正常，5.6及以下版本未进行测试



# 实现原理

 1. 通过pypcap获取数据包，利用dpkt进行解包
 2. 通过mysql协议发包回报过程组装session
 3. 执行时间利用session开始结束时间进行计算(pypcap在py2中返回的时间戳只精确到十毫秒，所以在代码中使用当前时间做计算，会存在偏差)
 4. 执行操作的用户名获取方式分为两种，如果是新建连接通过解包获取，如果是已经存在的长连接，通过后端数据库中processlist获取(前提是工具所获取的数据流后端就是mysql才能使用)

## 执行方式：

python tcp_audit.py -h 可以获取参数介绍

## 示例：

### 比如我在中间件层对后面3306端口的数据流进行监听：
	`python tcp_audit.py -e eth0 -p 3306 -t src -u username -P password`  
### 如果是对本地端口进行监听，比如我们中间件层端口为6001： 
	`python tcp_audit.py -e eth0 -p 6001 -t des` （这里未提供用户名密码，因为中间件改变了来源信息，而我监听的是应用到中间件这层的数据流，所以不能直接获取链接所使用的用户，只能使用默认的解包获取）

## 获取内容打印如下：

	2019-08-06 08:52:22,984  INFO  log.py : INFO  source_host: 10.1.11.59 source_port: 59272 destination_host: 10.1.1.46 destination_port: 3306 user_name: test01 sql: INSERT INTO proxy_heart_beat.tb_heartbeat (p_id, p_ts) VALUES('?', '?') values: None execute_time:0.0001  status:#42000INSERT, UPDATE command denied to user 'test01'@'10.1.11.59' for table 'tb_heartbeat'

## 特别提醒：

 1. 如果数据流非常大，该工具会使用不小的cpu时间
 2. 日志保存在log目录，且默认10分钟切割一次，保留一个小时的数据，如有需要可自行修改log.py中的配置

## 需求的包：

dpkt、psutil、pypacp、pymysql

### 有任何疑问或使用中的问题可以加qq群(479472450)交流


