package cognitojwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
)

// the jwksUrl is in the format https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
const jwksUrl = "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"

const issuer = "cognito-idp"

// the jwk data structure follow the format specified here
// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-2
type jwk struct {
	Kid string
	Alg string
	Kty string
	E   string
	N   string
	Use string
}

func (cj *JWTClient) validate(toketStr string) (*jwt.Token, error) {
	jwks, err := getJWK(cj.Region, cj.UserPoolID)
	if err != nil {
		return &jwt.Token{}, err
	}

	token, err := jwt.Parse(toketStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("signing method: %s", token.Header["alg"])
		}

		kid, err := getStringClaim(token.Header, "kid")
		if err != nil {
			return "", err
		}

		webKey, ok := jwks[kid]
		if !ok {
			return "", errors.New("kid is invalid")
		}

		return getRSAPubKey(webKey.E, webKey.N), nil
	})

	if err != nil {
		return token, err
	}

	claims := token.Claims.(jwt.MapClaims)
	if err := validateJWTClaims(claims, cj.UserPoolID); err != nil {
		return token, err
	}

	if token.Valid {
		return token, nil
	}

	return token, err
}

func validateJWTClaims(claims jwt.MapClaims, userPoolID string) error {
	if err := validateISS(userPoolID, claims); err != nil {
		return err
	}

	if err := validateTokenUse(claims); err != nil {
		return err
	}

	return nil
}

func validateISS(userPoolID string, claims jwt.MapClaims) error {
	iss := fmt.Sprintf("https://%s.%s.amazonaws.com/%s", issuer, os.Getenv("REGION"), userPoolID)
	issuerClaim, err := getStringClaim(claims, "iss")
	if err != nil {
		return err
	}

	if strings.Contains(issuerClaim, issuer) {
		return validateClaimMatch("iss", []string{iss}, claims)
	}

	return errors.New("aws cognito is not the issuer of this token")

}

func validateTokenUse(claims jwt.MapClaims) error {
	use, err := getStringClaim(claims, "token_use")
	if err != nil {
		return err
	}

	if use == "sig" || use == "access" {
		return nil
	}

	return errors.New("invalid use claim")
}

func validateClaimMatch(key string, match []string, claims jwt.MapClaims) error {
	c, err := getStringClaim(claims, key)
	if err != nil {
		return err
	}

	for _, m := range match {
		if c == m {
			return nil
		}
	}

	return errors.New(fmt.Sprintf("%s should match any of the %s values", key, strings.Join(match, "|")))
}

func getRSAPubKey(E, N string) *rsa.PublicKey {
	decE, err := base64.RawURLEncoding.DecodeString(E)
	if err != nil {
		log.Fatalf("decoding exponent value for the RSA public key: %s", err)
	}

	if len(decE) < 4 {
		tempE := make([]byte, 4)
		copy(tempE[4-len(decE):], decE)
		decE = tempE
	}

	pubKey := &rsa.PublicKey{
		E: int(binary.BigEndian.Uint32(decE[:])),
		N: &big.Int{},
	}

	decN, err := base64.RawURLEncoding.DecodeString(N)
	if err != nil {
		log.Fatalf("decoding modulus value for the RSA public key: %s", err)
	}

	pubKey.N.SetBytes(decN)

	return pubKey
}

func getJWK(region, UserPoolID string) (map[string]jwk, error) {
	url := fmt.Sprintf(jwksUrl, region, UserPoolID)
	res, err := http.Get(url)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("get jwks: %s", err))
	}

	defer res.Body.Close()

	var jwks struct {
		Keys []jwk
	}

	json.NewDecoder(res.Body).Decode(&jwks)
	jwkM := make(map[string]jwk)
	for _, j := range jwks.Keys {
		jwkM[j.Kid] = j
	}

	return jwkM, nil
}

func getStringClaim(m map[string]interface{}, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", errors.New(fmt.Sprintf("%s does not exist", key))
	}

	vStr, ok := v.(string)
	if !ok {
		return "", errors.New(fmt.Sprintf("%s is not a string, current tyoe (%T)", key, v))
	}

	return vStr, nil
}
