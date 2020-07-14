package cognitojwt

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/dgrijalva/jwt-go"
	"log"
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

type Attribute struct {
	Name string
	Value string
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

type RegisterOutput struct {
	ID string
	UserConfirmed bool
}

func (cj *JWTClient) Register(username, password string, attributes ...Attribute) (RegisterOutput, error) {
	var userAttr []*cognito.AttributeType
	for _, attr := range attributes {
		userAttr = append(userAttr, &cognito.AttributeType{
			Name:  aws.String(attr.Name),
			Value: aws.String(attr.Value),
		})
	}

	user := &cognito.SignUpInput{
		Username: aws.String(username),
		Password: aws.String(password),
		ClientId: aws.String(cj.AppClientID),
		UserAttributes: userAttr,
	}

	output, err := cj.CognitoClient.SignUp(user)
	if err != nil {
		return RegisterOutput{}, err
	}

	return RegisterOutput{
		ID: *output.UserSub,
		UserConfirmed: *output.UserConfirmed,
	}, nil
}

func (cj *JWTClient) ValidateJWT(jwt string) (*jwt.Token, error) {
	return cj.validate(jwt)
}

func (cj *JWTClient) GetUserAttributes(username string) ([]Attribute, error) {
	output, err := cj.CognitoClient.AdminGetUser(&cognito.AdminGetUserInput{
		UserPoolId: aws.String(cj.UserPoolID),
		Username:   aws.String(username),
	})

	if err != nil {
		return []Attribute{}, err
	}

	var userAttributes []Attribute
	for _, attr := range output.UserAttributes {
		userAttributes = append(userAttributes, Attribute{
			Name:  aws.StringValue(attr.Name),
			Value: aws.StringValue(attr.Value),
		})
	}

	return userAttributes, nil
}