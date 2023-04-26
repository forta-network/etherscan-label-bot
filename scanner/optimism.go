package scanner

import (
	"sort"
	"strings"
)

type optimismParser struct{}

func (p *optimismParser) URLPatterns() []string {
	return []string{
		"https://optimistic.etherscan.io/token/%s",
		"https://optimistic.etherscan.io/address/%s",
	}
}

func (p *optimismParser) ExtractTags(body string) []string {
	// red labels
	red := extractAllBetween(body, "<span class=\"u-label u-label--xs u-label--danger\">", "<")
	// blue, yellow & grey labels
	rest := extractAllBetween(body, "/accounts/label/", "'")
	result := append(red, rest...)
	sort.Strings(result)
	return result
}
 
func (p *optimismParser) ExtractName(body string) string {
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
