package model

import (
	//"github.com/jinzhu/gorm"
	"gorm.io/gorm"
)

type Forget struct {
	gorm.Model
	Token string `gorm:"not null;size:100"`
	Email string `gorm:"unique;not null;size:100"`
}

func InsertForget(db *gorm.DB, token, email string) error {
	//user := User{Passwd: "mimahenfuz18.1_%1x", Email: "john@example.com"}
	model := Forget{Token: token, Email: email}
	result := db.Create(&model)
	if result.Error != nil {
		// 错误处理
		return result.Error
	}
	return nil
}
