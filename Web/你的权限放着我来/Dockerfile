# 使用 Golang 官方提供的安装镜像 golang:alpine 作为构建镜像
FROM golang:alpine AS builder

# 安装GCC和相关构建工具
RUN apk add build-base

# 设置工作目录
WORKDIR /app

# 将项目的源代码复制到镜像中
COPY . .

# 编译 Go 项目
RUN go build -o myapp

# 使用多阶段构建以减小最终镜像的大小
FROM alpine:latest
ENV Flag=flag{test_flag}
# 设置工作目录
WORKDIR /app

# 将构建阶段生成的可执行文件复制到最终镜像中
COPY --from=builder /app/myapp .
COPY templates /app/templates
COPY static /app/static

# 安装 SQLite 运行时依赖
RUN apk add --no-cache --upgrade sqlite

# 暴露应用程序运行的端口
EXPOSE 8080

# 设置容器启动命令
CMD ["./myapp"]