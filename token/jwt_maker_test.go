package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
	"github.com/techschool/simplebank/util"
)

func TestJWTMaker(t *testing.T) {
	maker, err := NewJWTMaker(util.RandomString(32))
	require.NoError(t, err)

	username := util.RandomOwner()
	role := "user"
	duration := time.Minute
	tokenType := TokenTypeAccessToken

	issuedAt := time.Now()
	expiredAt := issuedAt.Add(duration)

	token, payload, err := maker.CreateToken(username, role, duration, tokenType)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	verifiedPayload, err := maker.VerifyToken(token, tokenType)
	require.NoError(t, err)
	require.NotEmpty(t, verifiedPayload)

	require.NotZero(t, verifiedPayload.ID)
	require.Equal(t, username, verifiedPayload.Username)
	require.Equal(t, role, verifiedPayload.Role)
	require.Equal(t, tokenType, verifiedPayload.Type)
	require.WithinDuration(t, issuedAt, verifiedPayload.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, verifiedPayload.ExpiredAt, time.Second)
}

func TestExpiredJWTToken(t *testing.T) {
	maker, err := NewJWTMaker(util.RandomString(32))
	require.NoError(t, err)

	username := util.RandomOwner()
	role := "user"
	duration := -time.Minute
	tokenType := TokenTypeAccessToken

	token, payload, err := maker.CreateToken(username, role, duration, tokenType)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	verifiedPayload, err := maker.VerifyToken(token, tokenType)
	require.Error(t, err)
	require.EqualError(t, err, ErrExpiredToken.Error())
	require.Nil(t, verifiedPayload)
}

func TestInvalidJWTTokenAlgNone(t *testing.T) {
	payload, err := NewPayload(
		util.RandomOwner(),
		"user",
		time.Minute,
		TokenTypeAccessToken,
	)
	require.NoError(t, err)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodNone, payload)

	token, err := jwtToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	maker, err := NewJWTMaker(util.RandomString(32))
	require.NoError(t, err)

	payload, err = maker.VerifyToken(token, TokenTypeAccessToken)
	require.Error(t, err)
	require.EqualError(t, err, ErrInvalidToken.Error())
	require.Nil(t, payload)
}
