package scanner

import (
	"sort"
	"strings"
)

type arbitrumParser struct{}

func (p *arbitrumParser) URLPatterns() []string {
	return []string{
		"https://www.arbiscan.io/token/%s",
		"https://www.arbiscan.io/address/%s",
	}
}

func (p *arbitrumParser) ExtractTags(body string) []string {
	labels := extractAllBetween(body, "/accounts/label/", "'")
	sort.Strings(labels)
	return labels
}
 
func (p *arbitrumParser) ExtractName(body string) string {
	tokens := strings.Split(body, " | address 0x")
	if len(tokens) > 1 {
		htmlTokens := strings.Split(tokens[0], ">")
		if len(htmlTokens) > 0 {
			name := strings.Split(htmlTokens[len(htmlTokens)-1], "|")[0]
			return strings.TrimSpace(name)
		}
	}
	return ""
}
