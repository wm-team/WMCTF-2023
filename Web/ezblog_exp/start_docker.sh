#!/bin/sh

set -x
set -e

cd exp_docker

docker build . -t ezblog_exp

docker run -it -p 3306:3306 --rm ezblog_exp