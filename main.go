package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/sns"
)

type OTPRequest struct {
	Identifier string `json:"identifier"`
	Method     string `json:"method"`
}

type OTPVerifyRequest struct {
	Identifier string `json:"identifier"`
	OTP        string `json:"otp"`
}

func generateOTP() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func sendOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var otpReq OTPRequest
	err := json.Unmarshal([]byte(request.Body), &otpReq)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: "Invalid request body"}, nil
	}

	otp := generateOTP()

	sess := session.Must(session.NewSession())

	// Store OTP in DynamoDB
	dynamoClient := dynamodb.New(sess)
	_, err = dynamoClient.PutItem(&dynamodb.PutItemInput{
		TableName: aws.String("OTP"),
		Item: map[string]*dynamodb.AttributeValue{
			"Identifier": {S: aws.String(otpReq.Identifier)},
			"CreatedAt":  {N: aws.String(strconv.FormatInt(time.Now().Unix(), 10))},
			"OTP":        {S: aws.String(otp)},
		},
	})
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Failed to store OTP"}, err
	}

	switch otpReq.Method {
	case "sms":
		snsClient := sns.New(sess)
		_, err = snsClient.Publish(&sns.PublishInput{
			Message:     aws.String(fmt.Sprintf("Your OTP is: %s", otp)),
			PhoneNumber: aws.String(otpReq.Identifier),
		})
	case "email":
		sesClient := ses.New(sess)
		_, err = sesClient.SendEmail(&ses.SendEmailInput{
			Source: aws.String("your-verified-email@example.com"),
			Destination: &ses.Destination{
				ToAddresses: []*string{aws.String(otpReq.Identifier)},
			},
			Message: &ses.Message{
				Subject: &ses.Content{
					Data: aws.String("Your OTP"),
				},
				Body: &ses.Body{
					Text: &ses.Content{
						Data: aws.String(fmt.Sprintf("Your OTP is: %s", otp)),
					},
				},
			},
		})
	default:
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: "Invalid method"}, nil
	}

	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Failed to send OTP"}, err
	}

	return events.APIGatewayProxyResponse{StatusCode: 200, Body: "OTP sent successfully"}, nil
}

func verifyOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var verifyReq OTPVerifyRequest
	err := json.Unmarshal([]byte(request.Body), &verifyReq)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: "Invalid request body"}, nil
	}

	sess := session.Must(session.NewSession())
	dynamoClient := dynamodb.New(sess)

	result, err := dynamoClient.Query(&dynamodb.QueryInput{
		TableName:              aws.String("OTP"),
		KeyConditionExpression: aws.String("Identifier = :id"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":id": {S: aws.String(verifyReq.Identifier)},
		},
		ScanIndexForward: aws.Bool(false),
		Limit:            aws.Int64(1),
	})

	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Failed to retrieve OTP"}, err
	}

	if len(result.Items) == 0 {
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: "No OTP found"}, nil
	}

	storedOTP := *result.Items[0]["OTP"].S
	createdAt, _ := strconv.ParseInt(*result.Items[0]["CreatedAt"].N, 10, 64)

	if time.Now().Unix()-createdAt > 300 { // OTP expires after 5 minutes
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: "OTP expired"}, nil
	}

	if verifyReq.OTP != storedOTP {
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: "Invalid OTP"}, nil
	}

	return events.APIGatewayProxyResponse{StatusCode: 200, Body: "OTP verified successfully"}, nil
}

func main() {
	lambda.Start(handleRequest)
}

func handleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	switch request.Resource {
	case "/send-otp":
		return sendOTP(request)
	case "/verify-otp":
		return verifyOTP(request)
	default:
		return events.APIGatewayProxyResponse{StatusCode: 404, Body: "Not Found"}, nil
	}
}
