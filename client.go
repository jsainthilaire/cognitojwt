package cognito_jwt

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"log"
	"os"
)

const flowUsernamePassword = "USER_PASSWORD_AUTH"

type JWTClient struct {
	UserPoolID    string
	AppClientID   string
	CognitoClient *cognito.CognitoIdentityProvider
	Region        string
}

func NewClient(region, userPoolID, appClientID string) *JWTClient {
	awsConfig := &aws.Config{Region: aws.String(region)}
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		log.Fatalf("new session: %s", err)
	}

	jc := JWTClient{
		UserPoolID:    userPoolID,
		AppClientID:   appClientID,
		CognitoClient: cognito.New(sess),
		Region:        region,
	}

	return &jc
}

type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

type User struct {
	Username string
	Password string
}

func (cj *JWTClient) Login(username, password string) (Token, error) {
	params := map[string]*string{
		"USERNAME": aws.String(username),
		"PASSWORD": aws.String(password),
	}

	auth := &cognito.InitiateAuthInput{
		ClientId:       aws.String(cj.AppClientID),
		AuthFlow:       aws.String(flowUsernamePassword),
		AuthParameters: params,
	}

	res, err := cj.CognitoClient.InitiateAuth(auth)
	if err != nil {
		return Token{}, err
	}

	return Token{
		AccessToken:  *res.AuthenticationResult.AccessToken,
		RefreshToken: *res.AuthenticationResult.RefreshToken,
		ExpiresIn:    *res.AuthenticationResult.ExpiresIn,
	}, nil
}
