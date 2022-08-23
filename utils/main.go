package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/b3nard/go-jwt-api/models"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"net/http"
	"os"
	"strings"
	"time"
)

var DbConn *gorm.DB
var err error

func InitDB() {
	uri := os.Getenv("DB_URI")
	DbConn, err = gorm.Open(mysql.Open(uri), &gorm.Config{})
	if err != nil {
		fmt.Printf("[ERROR] DATABASE CONNECTION ERROR: %v", err)
	}
	fmt.Println("[INFO] Database Connection Successful")
}

func HashPassword(password string) ([]byte, error) {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hashPassword, nil
}

func VerifyPassword(hashPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashPassword), []byte(password))
	return err == nil
}

func CreateJWT(userId interface{}) (string, error) {
	// Implement JWT Signing
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	claims["user_id"] = userId
	key := []byte(os.Getenv("SECRET_KEY"))
	tokenString, err := token.SignedString(key)
	if err != nil {
		fmt.Printf("[ERROR] Error Signing JWT: %v \n", err)
		return "", err
	}
	return tokenString, nil
}

func VerifyJWT(next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("Authorization")
		name, tokenHeader, ok := strings.Cut(tokenHeader, " ")
		name, tokenHeader = strings.TrimSpace(name), strings.TrimSpace(tokenHeader)
		if !ok || name != "Token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "Unauthorized"})
			return
		}
		token, err := jwt.Parse(tokenHeader, func(t *jwt.Token) (interface{}, error) {
			_, ok := t.Method.(*jwt.SigningMethodHMAC)

			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "Unauthorized"})
			}
			return []byte(os.Getenv("SECRET_KEY")), nil
		})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "Unauthorized"})
			return
		}
		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "Invalid Token"})
			return
		} else {
			userId, _ := token.Claims.(jwt.MapClaims)["user_id"]
			fmt.Println("User Id: ", userId)
			next(w, r)
		}

	}
}

// LoadEnv : Loads .env file and set environment variables.
func LoadEnv() {
	fmt.Println("[INFO] Loading .env variables...")
	path, _ := os.Getwd()
	f, err := os.Open(string(path) + "/.env")
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("[ERROR] N.env file exist in the app root directory")
			err := f.Close()
			if err != nil {
				return
			}
			return
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		os.Setenv(key, value)

	}
	fmt.Println("[INFO] Done Loading .env variables")
}
