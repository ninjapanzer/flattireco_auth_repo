package authorization_token_repo

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"log"
	"os"
	"strconv"
	"time"
)

type TokenEntity struct {
	Provider  string `json:Provider`
	Token     string `json:Token`
	TokenType string `json:TokenType`
	ExpiresIn int16  `json:ExpiresIn`
	CreatedAt int64  `json:CreatedAt`
}

func (token TokenEntity)IsExpired() (bool) {
	log.Print("Created At: " + strconv.FormatInt(token.CreatedAt, 10))
	var expirationTimestamp = token.CreatedAt + int64(token.ExpiresIn - 60)
	log.Print("Expires At: " + strconv.FormatInt(expirationTimestamp, 10))
	log.Print("Now: " + strconv.FormatInt(time.Now().Unix(), 10))
	log.Print("Expired?: " + strconv.FormatBool(time.Now().Unix() > expirationTimestamp))
	return time.Now().Unix() > expirationTimestamp
}

var ddb *dynamodb.DynamoDB
var tableName = aws.String("authTable")

func init() {
	region := os.Getenv("AWS_REGION")
	if session, err := session.NewSession(&aws.Config{ // Use aws sdk to connect to dynamoDB
		Region: &region,
	}); err != nil {
		fmt.Println(fmt.Sprintf("Failed to connect to AWS: %s", err.Error()))
	} else {
		ddb = dynamodb.New(session) // Create DynamoDB client
	}
}

func SaveRefresh(
	token string,
	expiresIn int16,
) {
	save(token, "refresh", expiresIn)
}

func SaveBearer(
	token string,
	expiresIn int16,
) {
	save(token, "bearer", expiresIn)
}

func save(
	token string,
	tokenType string,
	expiresIn int16,
) {
	tokenEntity := &TokenEntity{
		Provider:  "lightspeed",
		Token:     token,
		TokenType: tokenType,
		ExpiresIn: expiresIn,
		CreatedAt: time.Now().Unix(),
	}

	item, _ := dynamodbattribute.MarshalMap(tokenEntity)
	input := &dynamodb.PutItemInput{
		Item:      item,
		TableName: tableName,
	}
	if _, err := ddb.PutItem(input); err != nil {
		log.Print(err)
	} else {
		log.Print("saved tokens for lightspeed")
		return
	}

	return
}

var lightspeedFilter = expression.Name("Provider").Equal(expression.Value("lightspeed"))

func Fetch(provider string) (TokenEntity, TokenEntity) {

	expr, err := expression.NewBuilder().WithFilter(lightspeedFilter).Build()

	result, err := ddb.Scan(&dynamodb.ScanInput{
		ConsistentRead:            aws.Bool(true),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		TableName:                 tableName,
	})

	if err != nil {
		log.Print(err)
	}

	return extractTokens(result)
}

func extractTokens(result *dynamodb.ScanOutput) (bearer TokenEntity, refresh TokenEntity) {
	for _, i := range result.Items {
		item := TokenEntity{}

		err := dynamodbattribute.UnmarshalMap(i, &item)

		if err != nil {
			fmt.Println("Got error unmarshalling:")
			fmt.Println(err.Error())
			os.Exit(1)
		}

		// Which ones had a higher rating than minimum?
		if item.TokenType == "bearer" {
			bearer = item
		}

		if item.TokenType == "refresh" {
			refresh = item
		}
	}

	return
}
