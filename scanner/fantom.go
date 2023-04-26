package scanner

import (
	"sort"
	"strings"
)

type fantomParser struct{}

func (p *fantomParser) URLPatterns() []string {
	return []string{
		"https://ftmscan.com/token/%s",
		"https://ftmscan.com/address/%s",
	}
}

func (p *fantomParser) ExtractTags(body string) []string {
	labels := extractAllBetween(body, "/accounts/label/", "'")
	sort.Strings(labels)
	return labels
}
 
func (p *fantomParser) ExtractName(body string) string {
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
