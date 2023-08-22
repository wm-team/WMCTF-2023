package model

import (
	//"github.com/jinzhu/gorm"
	"gorm.io/gorm"
)

// User
//type User struct {
//	ID       int    `gorm:"primaryKey"`               //设置为主键
//	Username string `gorm:"not null;unique;size:255"` //唯一，不为空
//	Password string `gorm:"not null"`
//	Mobile   string `gorm:"unique;not null;"`
//}

type User struct {
	gorm.Model
	Username string `gorm:"not null;size:30"`
	Password string `gorm:"not null;size:40"`
	Role     string `gorm:"not null;size:40;default:user"`
	Email    string `gorm:"unique;not null;size:100"` //唯一，不为空
}

func IsEmailExist(db *gorm.DB, email string) bool {
	var user User
	db.Where("email = ?", email).First(&user)
	if user.ID != 0 {
		return true
	}
	return false
}
