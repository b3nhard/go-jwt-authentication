package main

import (
	"encoding/json"
	"fmt"
	"github.com/b3nard/go-jwt-api/models"
	"github.com/b3nard/go-jwt-api/utils"
	_ "github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
	"os"
)

func SignIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var cred models.Credentials

	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		fmt.Println("Error Unmarshalling")
		return
	}
	var user models.User
	utils.DbConn.Where("email=?", cred.Email).Find(&user)
	ok := utils.VerifyPassword(user.Password, cred.Password)
	if user.Email == "" || !ok {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "Invalid Credentials"})
		return
	}
	if !utils.VerifyPassword(user.Password, cred.Password) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "Invalid Credentials"})
		return
	} else {
		token, err := utils.CreateJWT(user.Id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "Success", Data: "Token " + token})
	}
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var cred models.Credentials
	_ = json.NewDecoder(r.Body).Decode(&cred)

	hash, _ := utils.HashPassword(cred.Password)
	id, _ := uuid.NewUUID()
	user := models.User{
		Id:       id,
		Name:     cred.Name,
		Email:    cred.Email,
		Password: string(hash),
		Role:     "User",
	}

	err := utils.DbConn.Debug().Create(&user).Error

	if err != nil {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "User with Email " + cred.Email + " Already Exists"})
		return
	}
	token, _ := utils.CreateJWT(user.Id)
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(models.JsonResponse{Message: "Created", Data: "Token " + token})
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(models.JsonResponse{
		Message: "Super Secret Area",
	})

}

func main() {
	utils.LoadEnv() // Load .env Variables
	utils.InitDB()
	err := utils.DbConn.AutoMigrate(&models.User{})
	if err != nil {
		return
	}
	fmt.Println("[INFO] Migrated Database")
	http.HandleFunc("/api", utils.VerifyJWT(rootHandler))
	http.HandleFunc("/api/sign-in", SignIn)
	http.HandleFunc("/api/sign-up", SignUp)
	fmt.Printf("[INFO] Server running on port http://127.0.0.1:%s \n", os.Getenv("PORT"))
	err = http.ListenAndServe(":8000", nil)
	if err != nil {
		return
	}
}
