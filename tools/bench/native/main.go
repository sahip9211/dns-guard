// Standalone diagnostic client. k6 remains the acceptance runner.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

type Case struct {
	Domain     string `json:"domain"`
	Categories uint32 `json:"categories"`
	Blocked    uint32 `json:"blocked"`
}
type Worker struct {
	Issued, Errors           int
	HTTP, Scheduled, Matcher []int64
}

func validateReply(r *http.Response, expected uint32) (int64, error) {
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", r.StatusCode)
	}
	ns, err := strconv.ParseInt(r.Header.Get("X-Lookup-Ns"), 10, 64)
	if err != nil || ns < 0 {
		return 0, fmt.Errorf("invalid matcher timing")
	}
	var result struct{ Blocked, Allowed, Enforced *uint32 }
	decoder := json.NewDecoder(io.LimitReader(r.Body, 512))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return 0, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return 0, fmt.Errorf("trailing or oversized response")
	}
	if result.Blocked == nil || result.Allowed == nil || result.Enforced == nil || *result.Blocked != expected || *result.Allowed > 127 || *result.Enforced > 127 {
		return 0, fmt.Errorf("incorrect policy response")
	}
	return ns, nil
}
func dueRequests(elapsed time.Duration, rate int) int64 {
	return int64(elapsed) * int64(rate) / int64(time.Second)
}
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(math.Ceil(float64(len(sorted))*p))-1]
}
func percentiles(values []int64) map[string]any {
	if len(values) == 0 {
		return map[string]any{"samples": 0, "p99_ms": nil}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return map[string]any{"samples": len(values), "p50_ms": float64(percentile(values, .5)) / 1e6, "p95_ms": float64(percentile(values, .95)) / 1e6, "p99_ms": float64(percentile(values, .99)) / 1e6, "max_ms": float64(values[len(values)-1]) / 1e6}
}
func main() {
	base := flag.String("base", "http://127.0.0.1:8787", "local harness URL")
	file := flag.String("cases", "tests/load/cases.json", "expected policies")
	duration := flag.Duration("duration", 30*time.Second, "arrival duration")
	rate := flag.Int("rate", 25000, "scheduled requests per second")
	workers := flag.Int("workers", 200, "maximum in-flight requests")
	flag.Parse()
	if *rate < 1 || *rate > 1000000 || *workers < 1 || *workers > 2048 || *duration <= 0 || *duration > 10*time.Minute || dueRequests(*duration, *rate) > 20000000 {
		panic("invalid or oversized probe")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		panic(err)
	}
	var cases []Case
	if err = json.Unmarshal(data, &cases); err != nil || len(cases) == 0 {
		panic("invalid cases")
	}
	transport := &http.Transport{MaxIdleConns: *workers, MaxIdleConnsPerHost: *workers, MaxConnsPerHost: *workers, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	urls := make([]string, len(cases))
	for i, c := range cases {
		urls[i] = fmt.Sprintf("%s/check/%d/%s", *base, c.Categories, c.Domain)
		r, err := client.Get(urls[i])
		if err != nil {
			panic(err)
		}
		if _, err = validateReply(r, c.Blocked); err != nil {
			panic(err)
		}
	}
	jobs := make(chan int64)
	stats := make([]Worker, *workers)
	var wait sync.WaitGroup
	var started time.Time
	// Workers block until the scheduling epoch is set and jobs are sent.
	for i := range stats {
		wait.Add(1)
		go func(w *Worker) {
			defer wait.Done()
			for n := range jobs {
				c := cases[n%int64(len(cases))]
				tick := time.Now()
				r, err := client.Get(urls[n%int64(len(urls))])
				w.Issued++
				if err != nil {
					w.Errors++
					continue
				}
				ns, err := validateReply(r, c.Blocked)
				finished := time.Now()
				w.HTTP = append(w.HTTP, finished.Sub(tick).Nanoseconds())
				w.Scheduled = append(w.Scheduled, finished.Sub(started.Add(time.Duration(n*int64(time.Second)/int64(*rate)))).Nanoseconds())
				if err != nil {
					w.Errors++
				} else {
					w.Matcher = append(w.Matcher, ns)
				}
			}
		}(&stats[i])
	}
	started = time.Now()
	total := dueRequests(*duration, *rate)
	ticker := time.NewTicker(time.Millisecond)
	var dispatched, dropped int64
	for dispatched < total {
		<-ticker.C
		due := dueRequests(time.Since(started), *rate)
		if due > total {
			due = total
		}
		// Do not replay missed scheduled requests after the arrival window ends.
		if time.Since(started) >= *duration {
			dropped += total - dispatched
			break
		}
		for dispatched < due {
			select {
			case jobs <- dispatched:
			default:
				dropped++
			}
			dispatched++
		}
	}
	ticker.Stop()
	close(jobs)
	wait.Wait()
	var combined Worker
	for _, w := range stats {
		combined.Issued += w.Issued
		combined.Errors += w.Errors
		combined.HTTP = append(combined.HTTP, w.HTTP...)
		combined.Scheduled = append(combined.Scheduled, w.Scheduled...)
		combined.Matcher = append(combined.Matcher, w.Matcher...)
	}
	output := map[string]any{"kind": "native-http-diagnostic-not-k6", "duration_s": duration.Seconds(), "target_per_s": *rate, "workers": *workers, "scheduled": total, "issued": combined.Issued, "correct": combined.Issued - combined.Errors, "errors": combined.Errors, "dropped": dropped, "handled_per_configured_second": float64(combined.Issued-combined.Errors) / duration.Seconds(), "http": percentiles(combined.HTTP), "schedule_to_completion": percentiles(combined.Scheduled), "matcher": percentiles(combined.Matcher), "note": "1ms arrival batches; bounded in-flight workers; missed arrivals remain drops. HTTP includes response decoding. Same-host diagnostic, not acceptance."}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		panic(err)
	}
}
