package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	Id       uuid.UUID `gorm:"primary key; unique; not null;"`
	Name     string    `gorm:"not null;"json:"name"`
	Email    string    `gorm:"not null;unique;" json:"email"`
	Password string    `gorm:"not null;" json:"-"`
	Role     string    `json:"role"`
	gorm.Model
}
type JsonResponse struct {
	Message string
	Data    string
}

type Credentials struct {
	Email    string
	Name     string
	Password string
}

type Payload struct {
	Id    uint
	Email string
}
