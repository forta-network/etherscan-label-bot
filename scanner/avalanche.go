package scanner

import (
	"sort"
	"strings"
)

type avalancheParser struct{}

func (p *avalancheParser) URLPatterns() []string {
	return []string{
		"https://snowtrace.io/token/%s",
		"https://snowtrace.io/address/%s",
	}
}

func (p *avalancheParser) ExtractTags(body string) []string {
	labels := extractAllBetween(body, "/accounts/label/", "'")
	sort.Strings(labels)
	return labels
}
 
func (p *avalancheParser) ExtractName(body string) string {
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
