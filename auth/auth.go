package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"peterdekok.nl/gotools/logger"
	"peterdekok.nl/gotools/router/writer"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User interface {
	GetId() string
	GetUsername() string
	GetPassword() []byte
}

type UserRepository interface {
	FromId(id string) User
	FromUsername(username string) User
}

type Auth struct {
	userRepository UserRepository

	accessSecret  []byte
	refreshSecret []byte

	accessTokens  map[uuid.UUID]*Token
	refreshTokens map[uuid.UUID]*Token

	sync.RWMutex
}

type Tokens struct {
	AccessToken  *Token `json:"access_token"`
	RefreshToken *Token `json:"refresh_token"`
}

type Token struct {
	Id        uuid.UUID `json:"-"`
	Signed    string    `json:"token"`
	ExpiresAt JSONTime  `json:"expires_at"`

	User User `json:"-"`

	parent *Token
}

type TokenDetails struct {
	AccessId uuid.UUID
	UserId   string
}

type JSONTime struct {
	time.Time
}

type LoginBody struct {
	Username string
	Password string
}

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
)

var (
	log logger.Logger
)

func init() {
	log = logger.New("router.auth")
}

func New(ur UserRepository, accessSecret, refreshSecret string) (*Auth, error) {
	var err error

	if ur == nil {
		err = errors.New("missing user repository")
	} else if len(accessSecret) < 64 {
		err = errors.New("accessSecret too short")
	} else if len(refreshSecret) < 64 {
		err = errors.New("refreshSecret too short")
	}

	if err != nil {
		log.WithError(err).Error("Failed to create new auth")

		return nil, err
	}

	return &Auth{
		userRepository: ur,
		accessSecret:   []byte(accessSecret),
		refreshSecret:  []byte(refreshSecret),
		accessTokens:   make(map[uuid.UUID]*Token),
		refreshTokens:  make(map[uuid.UUID]*Token),
	}, nil
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	log.Debug("Attempt login")

	body := &LoginBody{}

	d := json.NewDecoder(r.Body)

	if err := d.Decode(body); err != nil {
		err = fmt.Errorf("failed to login: %v", err)

		_ = writer.NewJsonError(http.StatusInternalServerError, "Invalid json", err).Write(w, log)

		return
	}

	l := log.WithField("user", body.Username)

	var (
		err  error
		user User
	)

	if len(body.Password) == 0 {
		err = errors.New("no password given")
	} else if user = a.userRepository.FromUsername(body.Username); user == nil {
		err = errors.New("user not found")
	} else if err = bcrypt.CompareHashAndPassword(user.GetPassword(), []byte(body.Password)); err == nil {
		token, err := a.CreateToken(user)

		if err != nil {
			_ = writer.NewJsonError(http.StatusUnprocessableEntity, nil, err).Write(w, l)

			return
		}

		_ = writer.Json(w, l, http.StatusOK, token)

		l.Info("Login success")

		return
	}

	err = fmt.Errorf("failed to login: %v", err)

	_ = writer.NewJsonError(http.StatusUnauthorized, "Invalid credentials", err).Write(w, l)
}

func (a *Auth) CreateToken(user User) (*Tokens, error) {
	rt := &Token{
		Id:        uuid.New(),
		ExpiresAt: JSONTime{time.Now().Add(7 * 24 * time.Hour)},
		User:      user,
	}

	at := &Token{
		Id:        uuid.New(),
		ExpiresAt: JSONTime{time.Now().Add(2 * time.Hour)},
		User:      user,
		parent:    rt,
	}

	ts := &Tokens{
		AccessToken:  at,
		RefreshToken: rt,
	}

	var err error

	// Access Token
	at.Signed, err = jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"access_id": at.Id.String(),
		"exp":       at.ExpiresAt,
		"user_id":   user.GetId(),
		"user_name": user.GetUsername(),
	}).SignedString(a.accessSecret)

	if err != nil {
		return nil, err
	}

	// Refresh Token
	rt.Signed, err = jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"refresh_id": rt.Id.String(),
		"exp":        rt.ExpiresAt,
		"user_id":    user.GetId(),
		"user_name":  user.GetUsername(),
	}).SignedString(a.refreshSecret)

	if err != nil {
		return nil, err
	}

	a.Lock()
	defer a.Unlock()

	a.accessTokens[at.Id] = at
	a.refreshTokens[rt.Id] = rt

	go a.AccessTokenTimeout(at)
	go a.RefreshTokenTimeout(rt)

	return ts, nil
}

func (a *Auth) AccessTokenTimeout(t *Token) {
	<-time.NewTimer(time.Until(t.ExpiresAt.Time)).C

	delete(a.accessTokens, t.Id)
}

func (a *Auth) RefreshTokenTimeout(t *Token) {
	<-time.NewTimer(time.Until(t.ExpiresAt.Time)).C

	delete(a.refreshTokens, t.Id)
	delete(a.accessTokens, t.parent.Id)
}

func (a *Auth) ExtractToken(r *http.Request) string {
	return ExtractTokenFromRequest(r, TokenTypeBearer)
}

func (a *Auth) ExtractAccessTokenMetadata(r *http.Request) (*TokenDetails, error) {
	tokenString := a.ExtractToken(r)

	if len(tokenString) == 0 {
		return nil, errors.New("token not found")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return a.accessSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if ok && token.Valid {
		accessIdString, ok := claims["access_id"].(string)

		if !ok {
			return nil, errors.New("invalid access id")
		}

		accessId, err := uuid.Parse(accessIdString)

		if err != nil {
			return nil, err
		}

		userId, ok := claims["user_id"].(string)

		if !ok {
			return nil, errors.New("invalid user id")
		}

		return &TokenDetails{
			AccessId: accessId,
			UserId:   userId,
		}, nil
	}
	return nil, err
}

func (a *Auth) IsValid(r *http.Request) (*Token, error) {
	var token *Token
	var ok bool

	tokenDetails, err := a.ExtractAccessTokenMetadata(r)

	if err == nil {
		a.RLock()
		defer a.RUnlock()

		token, ok = a.accessTokens[tokenDetails.AccessId]

		if !ok {
			err = errors.New("invalid token")
		}
	}

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (jt JSONTime) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(jt.Unix(), 10)), nil
}

func ExtractTokenFromRequest(r *http.Request, t TokenType) string {
	authHeader := r.Header.Get("Authorization")

	if len(t) > 0 {
		tokenParts := strings.SplitN(authHeader, string(t)+" ", 2)

		if len(tokenParts) == 2 {
			return tokenParts[1]
		}

		return ""
	}

	return authHeader
}

func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), 10)
}
