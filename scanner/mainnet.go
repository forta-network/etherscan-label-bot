package scanner

import (
	"sort"
	"strings"
)

type mainnetParser struct{}

func (p *mainnetParser) URLPatterns() []string {
	return []string{
		"https://etherscan.io/token/%s",
		"https://etherscan.io/address/%s",
	}
}

func (p *mainnetParser) ExtractTags(body string) []string {
	var result []string
	tokens := strings.Split(body, "<i class='far fa-hashtag'></i>")
	if len(tokens) > 1 {
		for i := 1; i < len(tokens); i++ {
			t := strings.Replace(tokens[i], "<span class='hash-tag text-truncate'>", "", 1)
			r := strings.TrimSpace(strings.Split(t, "<")[0])
			if r != "" {
				result = append(result, r)
			}
		}
	}
	// aids in testing
	sort.Strings(result)
	return result
}

func (p *mainnetParser) ExtractName(body string) string {
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
