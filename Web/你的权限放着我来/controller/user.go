package controller

import (
	"ctf/common"
	"ctf/model"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// Register 用户注册
func Register(c *gin.Context) {
	// 获取db
	db := common.GetDB()
	email := c.PostForm("email")
	username := c.PostForm("username")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirmPassword")
	//密码验证
	if len(password) < 6 || confirmPassword != password {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "密码不能小于6位或密码不一致",
		})
		return
	}
	//如果用户名为空,生成随机字符串
	if len(username) == 0 {
		username = RandomString(10)
	}
	if !common.IsEmailValid(email) || common.IsEmpty(email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "请输入正确的邮箱",
		})
		return
	}

	//判断邮箱是否存在
	if model.IsEmailExist(db, email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "当前邮箱已经注册",
		})
		return
	}
	//然后对密码进行加密
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 500,
			"msg":  "加密错误，重启docker",
		})
		return
	}
	newUser := &model.User{
		Email:    email,
		Username: username,
		Password: string(hashPassword),
	}
	db.Create(newUser)
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "注册成功",
	})
}

// Login 用户的登录接口
func Login(c *gin.Context) {
	db := common.GetDB()
	email := c.PostForm("email")
	password := c.PostForm("password")
	if !common.IsEmailValid(email) || common.IsEmpty(email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "请输入正确的邮箱",
		})
		return
	}
	if common.IsEmpty(password) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "密码不能为空",
		})
		return
	}
	if len(password) < 6 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "密码不能小于6位哦",
		})
		return
	}
	var user model.User
	//查询数据
	db.Where("email = ?", email).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "用户不存在",
		})
		return
	}
	//密码的对比
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "密码错误",
		})
		return
	}
	sessions := sessions.Default(c)
	sessions.Set("status", "logined")
	sessions.Set("email", user.Email)
	sessions.Set("username", user.Username)
	sessions.Set("role", user.Role)
	err := sessions.Save()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "登录失败，session生成失败，请找管理员或重启docker",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "登录成功",
	})

}

func Forget(c *gin.Context) {
	// 获取db
	db := common.GetDB()
	email := c.PostForm("email")
	if model.IsEmailExist(db, email) && common.IsEmailValid(email) {
		subject := "重置密码邮件"
		token := common.GetToken(32)
		body := fmt.Sprintf("hi,重置密码链接：http://%s/change?email=%s&token=%s", c.Request.Host, email, token) //获取当前域名
		err := common.SendEmail(email, subject, body)
		if err == nil {
			var forget model.Forget
			//查询数据
			db.First(&forget, "email = ?", email)
			//没有重置的情况下存储token
			if forget.ID == 0 {
				err := model.InsertForget(db, token, email)
				if err != nil {
					c.JSON(http.StatusUnprocessableEntity, gin.H{
						"code": 422,
						"msg":  "重新发送邮箱一次，多次不行请找管理员或重启docker",
					})
					return
				}
			} else {
				//弱之前重置过则更新token
				forget.Token = token
				db.Save(&forget)
			}
			c.JSON(http.StatusOK, gin.H{
				"code": 200,
				"msg":  "发送成功",
			})
			return
		} else {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"code": 422,
				"msg":  "邮件发送失败，多次不行请找管理员或重启docker",
			})
			return
		}
	} else {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "邮箱未注册或格式错误",
		})
	}

}

func Change(c *gin.Context) {
	db := common.GetDB()

	email := c.PostForm("email")
	token := c.PostForm("token")
	newPassword := c.PostForm("newPassword")
	confirmPassword := c.PostForm("confirmPassword")
	if newPassword != confirmPassword {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "密码不一致",
		})
		return
	}
	if len(newPassword) < 6 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "密码不能小于6位哦",
		})
		return
	}
	if common.IsEmpty(email) || !common.IsEmailValid(email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "邮箱不能为空或格式错误",
		})
		return
	}
	var user model.User
	//查询数据
	db.Where("email = ?", email).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "用户不存在",
		})
		return
	}
	var forget model.Forget
	//查询数据
	db.Where("email = ?", email).First(&forget)
	//降低难度
	//if common.IsEmpty(token) && user.Role == "admin" {
	//	c.JSON(http.StatusOK, gin.H{
	//		"code": 200,
	//		"msg":  "你离成功只差重启docker,再试一次",
	//	})
	//	return
	//}

	if forget.Token == token {
		if user.Role == "admin" {
			Flag := os.Getenv("Flag")
			c.JSON(http.StatusOK, gin.H{
				"code": 200,
				"msg":  Flag,
			})
			return
		}
		password, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		user.Password = string(password)
		db.Save(&user)
		if token != "" {
			c.JSON(http.StatusOK, gin.H{
				"code": 200,
				"msg":  "密码修改成功",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"code": 200,
				"msg":  "密码修改成功，该账号看到的内容有限哦",
			})
		}

		return
	} else {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": 422,
			"msg":  "token有误或不能为空",
		})
		return
	}

}

// RandomString 生成随机字符串
func RandomString(n int) string {
	var letters = []byte("abcdefghijklmnopqlstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_")
	result := make([]byte, n)
	rand.Seed(time.Now().Unix())
	for i := range result {
		result[i] = letters[rand.Intn(len(letters))]

	}
	return string(result)
}
