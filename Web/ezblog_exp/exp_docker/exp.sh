#!/bin/bash -e

service mysql start

mysql -uroot -proot -e "CREATE USER 'admin'@'%' IDENTIFIED BY '123456';"
mysql -uroot -proot -e "GRANT REPLICATION SLAVE ON *.* TO 'admin'@'%';"

service mysql stop

echo 'server_id = 2' >> /etc/mysql/mysql.conf.d/mysqld.cnf
echo 'log-bin = mysql-bin' >> /etc/mysql/mysql.conf.d/mysqld.cnf
echo 'binlog_checksum = NONE' >> /etc/mysql/mysql.conf.d/mysqld.cnf
echo 'binlog_format = STATEMENT' >> /etc/mysql/mysql.conf.d/mysqld.cnf
echo 'master_verify_checksum = OFF' >> /etc/mysql/mysql.conf.d/mysqld.cnf
echo 'secure_file_priv = ' >> /etc/mysql/mysql.conf.d/mysqld.cnf
sed -i 's/bind-address\t= 127.0.0.1/bind-address = 0.0.0.0/g' /etc/mysql/mysql.conf.d/mysqld.cnf
rm /var/lib/mysql/auto.cnf

service mysql start

mysql -uroot -proot -e "CREATE DATABASE if not exists AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci"

service mysql stop

python3 /exp.py

service mysql start

# for debug to show what happened
xxd /var/lib/mysql/mysql-bin.000001
mysql -uroot -proot -e "show master status;"
mysql -uroot -proot -e "show binlog events;"

sleep infinity

