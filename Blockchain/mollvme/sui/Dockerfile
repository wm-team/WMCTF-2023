FROM ubuntu:22.04

RUN apt update && apt install -y libpq-dev socat

COPY ./sui-test-validator /sui-test-validator
RUN chmod +x /sui-test-validator

ENV RUST_LOG="consensus=off"

CMD /sui-test-validator & socat TCP-LISTEN:13338,fork,reuseaddr TCP:localhost:9000 & socat TCP-LISTEN:13339,fork,reuseaddr TCP:localhost:9123