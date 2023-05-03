package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"context"

	"forta-network/go-agent/domain"
	"forta-network/go-agent/types"
	"github.com/chromedp/chromedp"
	log "github.com/sirupsen/logrus"
)

type myAgent struct {
	*types.Agent
}


func extractAllBetween(body, prefix, suffix string) []string {
	var result []string
	tokens := strings.Split(body, prefix)
	for i, t := range tokens {
		if i == 0 {
			continue
		}
		tag := strings.TrimSpace(strings.Split(t, suffix)[0])
		if tag != "" {
			result = append(result, tag)
		}
	}
	return result
}

func getBody(url string, ctx context.Context) (string, error) {
	res, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	body := strings.ToLower(string(b))
	if strings.Contains(body, "just a moment") {

		var htmlContent string
		err2 := chromedp.Run(ctx,
			chromedp.Navigate(url),
			chromedp.InnerHTML("html", &htmlContent, chromedp.ByQuery),
		)
		if err2 != nil {
			return "", err2
		}
		return strings.ToLower(htmlContent), err2
	} else {
		return body, err
	}
	
}

func getReportFromPage(p types.Parser, url string, ctx context.Context) *domain.AddressReport {
	logger := log.WithFields(log.Fields{
		"url": url,
	})
	body, err := getBody(url, ctx)
	if err != nil {
		logger.WithError(err).Error("error getting page (skipping)")
		return nil
	}

	return &domain.AddressReport{
		Name:        p.ExtractName(body),
		Tags:        p.ExtractTags(body),
		LastChecked: time.Now(),
	}
}

func Scan(p types.Parser, address string, ctx context.Context) *domain.AddressReport {
	rp := &domain.AddressReport{}
	for _, up := range p.URLPatterns() {
		ar := getReportFromPage(p, fmt.Sprintf(up, address), ctx)
		if ar != nil {
			rp.Merge(ar)
		}
	}
	return rp
}

func NewParser(chainID int64) types.Parser {
	if chainID == 1 {
		return &mainnetParser{}
	}
	if chainID == 56 {
		return &bscParser{}
	}
	if chainID == 137 {
		return &polygonParser{}
	}
	if chainID == 42161 {
		return &arbitrumParser{}
	}
	if chainID == 10 {
		return &optimismParser{}
	}
	if chainID == 43114 {
		return &avalancheParser{}
	}
	if chainID == 250 {
		return &fantomParser{}
	}
	return nil
}
