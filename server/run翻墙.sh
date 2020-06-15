#! /bin/bash
ps -ef|grep tcpfan |grep -v 'grep'|awk '{print $2}'|xargs kill -9
nohup ./tcpfan > udpout.log 2>&1 &