FROM ubuntu:22.04

RUN apt-get update && apt-get install -y xinetd python3 python3-pip git

RUN python3 -m pip install --no-cache-dir requests ecdsa gmpy2

RUN mkdir -p /app/server
RUN mkdir -p /app/mutator
RUN mkdir -p /app/misc

# Setup sui config
COPY ./misc /app/misc
RUN mkdir -p /root/.sui/sui_config/ && mv /app/misc/client.yaml /root/.sui/sui_config/client.yaml && mv /app/misc/sui.keystore /root/.sui/sui_config/sui.keystore
RUN chmod +x /app/misc/sui
RUN git clone -b testnet https://github.com/publicqi/sui.git /root/.move/https___github_com_publicqi_sui_git_framework__testnet

COPY ./server /app/server
COPY ./mutator /app/mutator

# Setup xinetd
RUN mv /app/misc/ctf.xinetd /etc/xinetd.d/ctf
RUN mv /app/misc/start.sh /start.sh

RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

RUN chmod +x /start.sh

CMD ["/start.sh"]

EXPOSE 5000