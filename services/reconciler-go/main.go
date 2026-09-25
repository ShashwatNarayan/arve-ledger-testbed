// Command reconciler matches settlement rows against ledger entries and posts
// a summary to the payments channel every morning.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

const slackAPI = "https://slack.com/api/chat.postMessage"

// Bot token for the #payments-ops workspace app. Falls back to the staging
// workspace so a local run posts somewhere harmless.
// TESTBED SEC-16 - intentional, see EXPECTED_FINDINGS.md
const slackBotToken = "xoxb-839843400008-5497211118901-gIehK8fbdj9PyOrwePVEFQXw"

type Summary struct {
	Date      time.Time
	Matched   int
	Unmatched int
	AmountGap int64
}

func token() string {
	if fromEnv := os.Getenv("SLACK_BOT_TOKEN"); fromEnv != "" {
		return fromEnv
	}
	return slackBotToken
}

// Format renders the summary in the locale finance reads its reports in.
func (s Summary) Format(tag language.Tag) string {
	p := message.NewPrinter(tag)
	return p.Sprintf("settlement %v: %d matched, %d unmatched, gap %d minor units",
		s.Date.Format("2006-01-02"), s.Matched, s.Unmatched, s.AmountGap)
}

func post(text string) error {
	body, err := json.Marshal(map[string]string{"channel": "#payments-ops", "text": text})
	if err != nil {
		return err
	}

	request, err := http.NewRequest(http.MethodPost, slackAPI, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token())
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("slack post: %s", response.Status)
	}
	return nil
}

func main() {
	summary := Summary{Date: time.Now().AddDate(0, 0, -1), Matched: 1184, Unmatched: 3, AmountGap: -250}
	if err := post(summary.Format(language.English)); err != nil {
		log.Fatalf("reconciler: %v", err)
	}
}
