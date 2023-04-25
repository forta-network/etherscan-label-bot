package scanner

import (
	"sort"
	"strings"
)

type polygonParser struct{}

func (p *polygonParser) URLPatterns() []string {
	return []string{
		"https://www.polygonscan.com/token/%s",
		"https://www.polygonscan.com/address/%s",
	}
}

func (p *polygonParser) ExtractTags(body string) []string {
	// red labels
	red := extractAllBetween(body, "<span class=\"u-label u-label--xs u-label--danger\">", "<")
	// yellow & grey labels
	rest := extractAllBetween(body, "/accounts/label/", "\"")

	result := append(red, rest...)
	sort.Strings(result)
	return result
}

func (p *polygonParser) ExtractName(body string) string {
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
