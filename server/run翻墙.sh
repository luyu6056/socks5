#! /bin/bash
ps -ef|grep server |grep -v 'grep'|awk '{print $2}'|xargs kill -9
nohup ./server > udpout.log 2>&1 &