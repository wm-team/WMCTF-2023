package main

import (
	"ctf/common"
	"ctf/controller"
	"ctf/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	store := cookie.NewStore([]byte("znjw1tmw-i3dl-7u2o-681f-13qdzjxl9q8z"))
	// 设置session中间件，参数mysession，指的是session的名字，也是cookie的名字
	// store是前面创建的存储引擎，我们可以替换成其他存储引擎
	router.Use(sessions.Sessions("mysession", store))
	//初始化数据
	_, err := common.InitDB()
	if err != nil {
		panic(err.Error())
	}

	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "static")
	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.tmpl", gin.H{
			"title": "用户登录",
		})
	})
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.tmpl", gin.H{
			"title": "用户登录",
		})
	})
	router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.tmpl", gin.H{
			"title": "用户注册",
		})
	})
	router.GET("/change", func(c *gin.Context) {
		token := c.Query("token")
		email := c.Query("email")
		c.HTML(http.StatusOK, "change.tmpl", gin.H{
			"title": "密码重置",
			"token": token,
			"email": email,
		})
	})
	router.GET("/forget", func(c *gin.Context) {
		c.HTML(http.StatusOK, "forget.tmpl", gin.H{
			"title": "密码找回",
		})
	})
	router.GET("/index", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("status") != "logined" {
			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"title": "用户登录",
			})
			return
		} else {
			var flag = "其他功能也许有意外收获哦"
			var username = session.Get("username")
			var role = session.Get("role")
			var users []model.User
			//查询数据
			db := common.GetDB()
			db.Find(&users)
			emails := make([]string, len(users))
			for i, user := range users {
				emails[i] = user.Email //将用户邮件名列表展示给比赛同学，方便进行下一步
			}
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"flag":     flag,
				"username": username,
				"emails":   emails,
				"role":     role,
				"users":    users,
			})
		}
	})

	router.POST("/api/register", controller.Register) //用户注册
	router.POST("/api/login", controller.Login)       //用户登录
	router.POST("/api/forget", controller.Forget)     //忘记密码找回-给邮箱发送token
	router.POST("/api/change", controller.Change)     //修改密码&& 这里存在flag
	router.Run(":8080")
}
