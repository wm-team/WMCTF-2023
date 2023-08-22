FROM python:3

#===========================================================
#更换apt源安装socat,并安装py3下的Crypto库(中途warning无影响可忽略)
#===========================================================

RUN apt-get update -y && \
    apt-get install socat -y && \
    pip install pycryptodome -i https://mirrors.aliyun.com/pypi/simple/

COPY task.py /usr/src/app/

#=======================
#socat将py脚本挂载到9999端口
#=======================

ENTRYPOINT socat -d -d TCP4-LISTEN:9999,tcpwrap=script,reuseaddr,fork EXEC:"/usr/bin/env python -u /usr/src/app/task.py"

EXPOSE 9999
