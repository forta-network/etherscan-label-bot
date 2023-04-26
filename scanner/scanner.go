package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"context"

	"forta-network/go-agent/domain"
	"github.com/chromedp/chromedp"
	log "github.com/sirupsen/logrus"
)

type Parser interface {
	ExtractName(body string) string
	ExtractTags(body string) []string
	URLPatterns() []string
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

func getBody(url string) (string, error) {
	res, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	body := strings.ToLower(string(b))
	
	if strings.Contains(body, "just a moment") {
		ctx, cancel := chromedp.NewContext(context.Background())
		defer cancel()

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

func getReportFromPage(p Parser, url string) *domain.AddressReport {
	logger := log.WithFields(log.Fields{
		"url": url,
	})
	body, err := getBody(url)
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

func Scan(p Parser, address string) *domain.AddressReport {
	rp := &domain.AddressReport{}
	for _, up := range p.URLPatterns() {
		ar := getReportFromPage(p, fmt.Sprintf(up, address))
		if ar != nil {
			rp.Merge(ar)
		}
	}
	return rp
}

func NewParser(chainID int64) Parser {
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
	return nil
}
