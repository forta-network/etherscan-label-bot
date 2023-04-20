package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"forta-network/go-agent/domain"
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
	return strings.ToLower(string(b)), err
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
	return nil
}
