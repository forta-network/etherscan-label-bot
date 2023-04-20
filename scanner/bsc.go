package scanner

import (
	"sort"
	"strings"
)

type bscParser struct{}

func (p *bscParser) URLPatterns() []string {
	return []string{
		"https://www.bscscan.com/token/%s",
		"https://www.bscscan.com/address/%s",
	}
}

func (p *bscParser) ExtractTags(body string) []string {
	// red labels
	red := extractAllBetween(body, "<span class='u-label u-label--xs u-label--danger'>", "<")
	// grey labels
	grey := extractAllBetween(body, "/accounts/label/", "'")

	result := append(red, grey...)
	sort.Strings(result)
	return result
}

func (p *bscParser) ExtractName(body string) string {
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
