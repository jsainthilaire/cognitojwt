package cognito_jwt

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"log"
	"os"
)

type JWTClient struct {
	UserPoolID    string
	AppClientID   string
	CognitoClient *cognito.CognitoIdentityProvider
	Region        string
}

func NewClient(region, UserPoolID, AppClientID string) *JWTClient {
	awsConfig := &aws.Config{Region: aws.String(region)}
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		log.Fatalf("new session: %s", err)
	}

	jc := JWTClient{
		UserPoolID:    os.Getenv("COGNITO_USER_POOL_ID"),
		AppClientID:   os.Getenv("COGNITO_APP_CLIENT_ID"),
		CognitoClient: cognito.New(sess),
		Region:        region,
	}

	return &jc
}
