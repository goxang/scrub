package scrub_test

import (
	"fmt"
	"log"

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
