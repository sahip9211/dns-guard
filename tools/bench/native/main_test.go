package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func reply(body, timing string, status int) *http.Response {
	h := http.Header{}
	if timing != "" {
		h.Set("X-Lookup-Ns", timing)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

func TestValidationRejectsBadBodiesStatusTimingAndWrongDecisions(t *testing.T) {
	good := `{"blocked":1,"allowed":0,"enforced":0}`
	for _, r := range []*http.Response{
		reply(good, "", 200), reply(good, "NaN", 200), reply(good, "-1", 200), reply(good, "10", 500),
		reply(`{"blocked":0,"allowed":0,"enforced":0}`, "10", 200),
		reply(`{"blocked":1}`, "10", 200), reply(good+`{}`, "10", 200),
		reply(`{"blocked":1,"allowed":256,"enforced":0}`, "10", 200),
	} {
		if _, err := validateReply(r, 1); err == nil {
			t.Fatal("accepted invalid response")
		}
	}
	ns, err := validateReply(reply(good, "12", 200), 1)
	if err != nil || ns != 12 {
		t.Fatalf("valid response: %d %v", ns, err)
	}
}

func TestScheduledWorkAndPercentiles(t *testing.T) {
	if dueRequests(1500*time.Microsecond, 25000) != 37 {
		t.Fatal("fractional request schedule")
	}
	if dueRequests(time.Second, 25000) != 25000 {
		t.Fatal("wrong total request count")
	}
	if percentile([]int64{1, 3, 9, 12}, .99) != 12 {
		t.Fatal("p99")
	}
	if percentile(nil, .99) != 0 {
		t.Fatal("empty internal sample list")
	}
}
