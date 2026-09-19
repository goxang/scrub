package scrub_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/goxang/scrub"
	"github.com/goxang/scrub/packs"
)

func Example() {
	s, err := scrub.New().
		Add(scrub.Rule{
			ID:      "pin",
			Pattern: `(?i)\bpin\b\s*[:=]\s*(?P<secret>\d{4,12})`,
			Anchors: []string{"pin"},
			Group:   "secret",
		}).
		Build()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(s.Redact("terminal=12345678 PIN: 4321 amount=1500"))
	// Output: terminal=12345678 PIN: [REDACTED] amount=1500
}

func ExampleScrubber_Find() {
	s := scrub.New().Add(packs.Secrets()...).MustBuild()

	for _, m := range s.Find(`{"password":"hunter2secret"}`) {
		fmt.Printf("%s at [%d,%d)\n", m.RuleID, m.Start, m.End)
	}
	// Output: secret.keyed at [13,26)
}

func ExampleScrubber_RedactBytes() {
	s := scrub.New().Add(packs.Payment()...).MustBuild()

	buf := make([]byte, 0, 128)
	buf = s.RedactBytes(buf, []byte(`{"pan":"4111111111111111"}`))
	fmt.Println(string(buf))
	// Output: {"pan":"[REDACTED]"}
}

func ExampleWithMarker() {
	s := scrub.New(scrub.WithMarker("***")).
		Add(scrub.Rule{
			ID:      "otp",
			Pattern: `(?i)otp=(?P<secret>\d+)`,
			Anchors: []string{"otp"},
			Group:   "secret",
		}).
		MustBuild()

	fmt.Println(s.Redact("otp=123456"))
	// Output: otp=***
}

// A mask keeps part of the value readable, which a fixed replacement cannot.
func ExampleRule_mask() {
	keepLastFour := func(pan string) string {
		const visible = 4
		if len(pan) <= visible {
			return strings.Repeat("*", len(pan))
		}
		return pan[:len(pan)-6-visible] + strings.Repeat("*", 6) + pan[len(pan)-visible:]
	}

	s := scrub.New(scrub.WithMarker("[MASKED]")).
		Add(scrub.Rule{
			ID: "pin", Anchors: []string{"pin"}, Group: "secret", Replace: "****",
			Pattern: `(?i)"pin"\s*:\s*"(?P<secret>\d{4,12})"`,
		}).
		Add(scrub.Rule{
			ID: "pan", Anchors: []string{"pan"}, Group: "secret", Mask: keepLastFour,
			Pattern: `(?i)"pan"\s*:\s*"(?P<secret>\d{12,19})"`,
		}).
		Add(scrub.Rule{
			ID: "otp", Anchors: []string{"otp"}, Group: "secret",
			Pattern: `(?i)"otp"\s*:\s*"(?P<secret>\d{4,8})"`,
		}).
		MustBuild()

	fmt.Println(s.Redact(`{"pin":"1234","pan":"5022291092740569","otp":"55555"}`))
	// Output: {"pin":"****","pan":"502229******0569","otp":"[MASKED]"}
}
