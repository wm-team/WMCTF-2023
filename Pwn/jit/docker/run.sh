docker build -t jit:latest .
docker run -it -d --name jit -p 9999:9999 jit:latest