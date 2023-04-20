package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Label struct {
	ItemId  string `dynamodbav:"itemId"`
	SortKey string `dynamodbav:"sortKey"`
	Entity  string `dynamodbav:"entity"`
	Label   string `dynamodbav:"label"`
}

type LabelStore interface {
	EntityExists(ctx context.Context, entity string) (bool, error)
	GetLabel(ctx context.Context, entity, label string) (*Label, error)
	PutLabel(ctx context.Context, entity, label string) error
}

var table = "prod-research-bot-data"

type labelStore struct {
	chainID int64
	botID   string
	db      DynamoDB
}

func (s *labelStore) itemId(entity string) string {
	ID := cleanTxt(fmt.Sprintf("%s|etherscan-labels|%s", s.botID, entity))
	if s.chainID == 1 {
		return ID
	}
	return fmt.Sprintf("%d|%s", s.chainID, ID)
}

func cleanTxt(txt string) string {
	return strings.ToLower(strings.TrimSpace(txt))
}

func (s *labelStore) EntityExists(ctx context.Context, entity string) (bool, error) {
	keyEx := expression.Key("itemId").Equal(expression.Value(s.itemId(entity)))
	expr, err := expression.NewBuilder().WithKeyCondition(keyEx).Build()
	if err != nil {
		return false, err
	}
	res, err := s.db.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &table,
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		Select:                    types.SelectCount,
	})
	if err != nil {
		return false, err
	}
	return res.Count > 0, nil
}

func (s *labelStore) GetLabel(ctx context.Context, entity, label string) (*Label, error) {
	res, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{
			"itemId":  &types.AttributeValueMemberS{Value: s.itemId(entity)},
			"sortKey": &types.AttributeValueMemberS{Value: cleanTxt(label)},
		},
		TableName: &table,
	})
	if err != nil {
		return nil, err
	}
	if res.Item == nil {
		return nil, nil
	}
	var result Label
	if err := attributevalue.UnmarshalMap(res.Item, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *labelStore) PutLabel(ctx context.Context, entity, label string) error {
	item, err := attributevalue.MarshalMap(&Label{
		ItemId:  s.itemId(entity),
		SortKey: cleanTxt(label),
		Entity:  cleanTxt(entity),
		Label:   cleanTxt(label),
	})
	if err != nil {
		return err
	}

	_, err = s.db.PutItem(ctx, &dynamodb.PutItemInput{
		Item:      item,
		TableName: &table,
	})

	return err
}

func NewLabelStore(ctx context.Context, chainID int64, botID string, secrets *Secrets) (LabelStore, error) {
	if botID == "" {
		panic("botID is nil")
	}
	if chainID == 0 {
		panic("chainID is 0")
	}
	db, err := NewDynamoDBClient(ctx, secrets)
	if err != nil {
		return nil, err
	}
	return &labelStore{
		chainID: chainID,
		botID:   botID,
		db:      db,
	}, nil
}
