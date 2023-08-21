package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("GLgC9u_9jgeX6b3MrkDcIFrU7NCA_UotUl8-TVDiSvKKCJXYvGdbG-YBd0sMWiBOtUiYNy6bSwIJCXj-1ga3Fg")

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenData struct {
	UserID        string `json:"user_id"`
	RefreshToken  string `json:"refresh_token"`
	ExpirationUTC int64  `json:"expiration_utc"`
}

var client *mongo.Client
var tokenCollection *mongo.Collection

func main() {
	// Подключение к базе данных
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, _ = mongo.Connect(context.Background(), clientOptions)
	tokenCollection = client.Database("newdb").Collection("tokens")

	r := mux.NewRouter()
	r.HandleFunc("/get-tokens", GetTokensHandler).Methods("GET")
	r.HandleFunc("/refresh-tokens", RefreshTokensHandler).Methods("POST")

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func GetTokensHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	// Создание Access токена
	accessToken := jwt.New(jwt.SigningMethodHS512)
	accessClaims := accessToken.Claims.(jwt.MapClaims)
	accessClaims["user_id"] = userID
	accessClaims["exp"] = time.Now().Add(time.Hour * 1).Unix() // Срок действия 1 час
	accessString, _ := accessToken.SignedString(jwtSecret)

	// Создание Refresh токена
	refreshToken := generateRefreshToken(userID)

	// Сохранение Refresh токена в базе данных
	refreshTokenData := RefreshTokenData{
		UserID:        userID,
		RefreshToken:  refreshToken,
		ExpirationUTC: time.Now().Add(time.Hour * 24 * 7).Unix(), // Срок действия 1 неделя
	}
	_, err := tokenCollection.InsertOne(context.Background(), refreshTokenData)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	tokenPair := TokenPair{
		AccessToken:  accessString,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenPair)
}

func RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.PostFormValue("refresh_token")

	// Поиск Refresh токена в базе данных
	filter := bson.M{"refresh_token": refreshToken}
	var refreshTokenData RefreshTokenData
	err := tokenCollection.FindOne(context.Background(), filter).Decode(&refreshTokenData)
	if err != nil {
		http.Error(w, "Invalid Refresh Token", http.StatusUnauthorized)
		return
	}

	// Проверка срока действия Refresh токена
	if time.Now().Unix() > refreshTokenData.ExpirationUTC {
		http.Error(w, "Expired Refresh Token", http.StatusUnauthorized)
		return
	}

	// Проверка соответствия хеша Refresh токена
	err = bcrypt.CompareHashAndPassword([]byte(refreshTokenData.RefreshToken), []byte(refreshToken))
	if err != nil {
		http.Error(w, "Invalid Refresh Token", http.StatusUnauthorized)
		return
	}

	// Создание нового Access токена
	accessToken := jwt.New(jwt.SigningMethodHS512)
	accessClaims := accessToken.Claims.(jwt.MapClaims)
	accessClaims["user_id"] = refreshTokenData.UserID
	accessClaims["exp"] = time.Now().Add(time.Hour * 1).Unix() // Срок действия 1 час
	accessString, _ := accessToken.SignedString(jwtSecret)

	tokenPair := TokenPair{
		AccessToken:  accessString,
		RefreshToken: refreshTokenData.RefreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenPair)
}

func generateRefreshToken(userID string) string {
	refreshTokenBytes := []byte(userID + ":" + time.Now().String())
	hashedToken, _ := bcrypt.GenerateFromPassword(refreshTokenBytes, bcrypt.DefaultCost)
	return base64.StdEncoding.EncodeToString(hashedToken)
}
