package common

import (
	"ctf/model"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"time"
)

var DB *gorm.DB

func GetDB() *gorm.DB {
	return DB
}

func InitDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("ctf.db"), &gorm.Config{})
	if err != nil {
		// 错误处理
		//panic("连接数据库失败" + err.Error())
		return nil, err
	}
	DB = db
	// 设置数据库连接池参数
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	CreateUserTable(db)
	CreateForgetTable(db)
	return db, nil
}

// 创建用户表及初始用户
func CreateUserTable(db *gorm.DB) error {
	// 迁移（创建表）
	err := db.AutoMigrate(&model.User{})
	if err != nil {
		// 错误处理
		return err
	}

	//对密码进行加密
	hashPasswordalice, _ := bcrypt.GenerateFromPassword([]byte("alice1234569"), bcrypt.DefaultCost)
	hashPasswordbob, _ := bcrypt.GenerateFromPassword([]byte("bob1234569"), bcrypt.DefaultCost)
	hashPasswordcharlie, _ := bcrypt.GenerateFromPassword([]byte("charlie1234569"), bcrypt.DefaultCost)
	hashPasswordadmin, _ := bcrypt.GenerateFromPassword([]byte("huomooz7-n6t31fi52riri5bd"), bcrypt.DefaultCost)
	// 定义要插入的用户数据
	users := []model.User{
		{Password: string(hashPasswordalice), Email: "alice@example.com", Username: "alice"},
		{Password: string(hashPasswordbob), Email: "bob@zhangkeji.com", Username: "bob"},
		{Password: string(hashPasswordcharlie), Email: "charlie@sanfeng.com", Username: "charlie"},
		{Password: string(hashPasswordadmin), Email: "jom@roomke.com", Username: "jom", Role: "admin"},
	}
	//user := User{Passwd: "mimahenfuz18.1_%1x", Email: "john@example.com"}
	result := db.Create(&users)
	if result.Error != nil {
		// 错误处理
		return err
	}
	return nil
}

// 创建用户表及初始用户
func CreateForgetTable(db *gorm.DB) error {
	// 迁移（创建表）
	err := db.AutoMigrate(&model.Forget{})
	if err != nil {
		// 错误处理
		return err
	}
	return nil
}
