package common

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

func GetToken(length int) string {
	// 定义可用字符集
	charset := "abcdefghijklmnopqrstuvwxyz0123456789"

	// 计算字符集的长度
	charsetLength := big.NewInt(int64(len(charset)))

	// 创建一个缓冲区，用于存储生成的随机字符
	buffer := make([]byte, length)

	// 生成随机字符
	for i := 0; i < length; i++ {
		randomIndex, _ := rand.Int(rand.Reader, charsetLength)
		buffer[i] = charset[randomIndex.Int64()]
	}

	// 格式化成所需的格式
	return fmt.Sprintf("%s-%s-%s-%s-%s", buffer[0:8], buffer[8:12], buffer[12:16], buffer[16:20], buffer[20:])
}

func IsEmpty(str string) bool {
	trimmedStr := strings.TrimSpace(str)
	return len(trimmedStr) == 0
}

func IsEmailValid(email string) bool {
	// 正则表达式模式
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	// 创建正则表达式对象
	reg := regexp.MustCompile(pattern)

	// 判断是否匹配正则表达式
	return reg.MatchString(email)
}
