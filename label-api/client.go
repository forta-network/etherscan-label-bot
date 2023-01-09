package label_api

import (
	"encoding/json"
	"fmt"
	"github.com/forta-network/forta-core-go/protocol"
	"net/http"
	"net/url"
	"strings"
)

const defaultLabelAPI = "https://api.forta.network/labels/state"
const paramsPattern = "?sourceIds=%s&labels=%s&entities=%s&limit=%d"

type Client interface {
	GetLabels(req *GetLabelsRequest) ([]*protocol.Label, error)
}

type client struct {
	apiUrl string
}

func getPage(apiUrl string, pageToken *int) (*LabelResponse, error) {
	u := apiUrl
	if pageToken != nil {
		u = fmt.Sprintf("%s&pageToken=%d", u, *pageToken)
	}

	var lr LabelResponse
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, err
	}
	return &lr, nil
}

func encodeAll(arr []string) []string {
	var res []string
	for _, s := range arr {
		res = append(res, url.PathEscape(s))
	}
	return res
}

func (c *client) GetLabels(req *GetLabelsRequest) ([]*protocol.Label, error) {
	limit := req.Limit
	if limit == 0 {
		limit = 10000
	}

	params := fmt.Sprintf(paramsPattern,
		strings.Join(encodeAll(req.SourceIDs), ","),
		strings.Join(encodeAll(req.Labels), ","),
		strings.Join(encodeAll(req.Entities), ","),
		limit)

	u := fmt.Sprintf("%s%s", c.apiUrl, params)
	var result []*protocol.Label
	page, err := getPage(u, nil)
	if err != nil {
		return nil, err
	}
	for len(page.Events) > 0 {
		for _, evt := range page.Events {
			result = append(result, &protocol.Label{
				EntityType: protocol.Label_ADDRESS,
				Entity:     evt.Label.Entity,
				Confidence: evt.Label.Confidence,
				Remove:     evt.Label.Remove,
				Label:      evt.Label.Label,
			})
		}
		if page.PageToken == nil {
			break
		}
		nextPage, err := getPage(u, page.PageToken)
		if err != nil {
			return nil, err
		}
		page = nextPage
	}
	return result, nil
}

func NewClient(apiUrl *string) Client {
	u := defaultLabelAPI
	if apiUrl != nil {
		u = *apiUrl
	}
	return &client{apiUrl: u}
}
