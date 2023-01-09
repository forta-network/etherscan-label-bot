package label_api

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClient_GetLabels(t *testing.T) {
	c := NewClient(nil)

	res, err := c.GetLabels(&GetLabelsRequest{
		SourceIDs: []string{"0x6f022d4a65f397dffd059e269e1c2b5004d822f905674dbf518d968f744c2ede"},
		Entities:  []string{"0xd2b1a0e2e733c7c2621963b183e7c769c7e1a94c"},
		Labels:    []string{"phish / hack"},
	})
	assert.NoError(t, err)

	t.Logf("%d", len(res))
}
