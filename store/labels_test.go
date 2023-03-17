package store

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLabelStore_GetLabel(t *testing.T) {
	ctx := context.Background()
	s, err := LoadSecretsFromFile("/home/slanders/forta/forta-research-secrets/secrets.json")
	assert.NoError(t, err)
	store, err := NewLabelStore(ctx, "test", s)
	assert.NoError(t, err)

	l, err := store.GetLabel(ctx, "entity", "label")
	assert.NoError(t, err)
	assert.Nil(t, l)

	err = store.PutLabel(ctx, "new-entity", "new-label")
	assert.NoError(t, err)

	lb, err := store.GetLabel(ctx, "new-entity", "new-label")
	assert.NoError(t, err)
	assert.Equal(t, "new-label", lb.Label)

	exists, err := store.EntityExists(ctx, "new-entity")
	assert.NoError(t, err)

	assert.True(t, exists)

}
