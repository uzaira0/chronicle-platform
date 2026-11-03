// Independent oracle for test_backup_schedule.py: reads schedules exactly as the backup sidecar's
// go-cron v0.0.11 does (gocron/go-cron.go Create: robfig/cron v3 parser with SecondOptional | Minute |
// Hour | Dom | Month | Dow | Descriptor) and walks robfig's own Next() to measure the real gaps.
//
// stdin: one JSON object per line {"schedule": "...", "start": "YYYY-MM-DD", "days": N}
// stdout: one JSON object per line {"error": "..."} or {"gap": seconds, "runs": count}; "gap" is null
// with fewer than two runs, and "error" is "never runs" when robfig finds no next activation.
package main

import (
	"bufio"
	"encoding/json"
	"os"
	"time"

	"github.com/robfig/cron/v3"
)

type request struct {
	Schedule string `json:"schedule"`
	Start    string `json:"start"`
	Days     int    `json:"days"`
}

type answer struct {
	Error string `json:"error,omitempty"`
	Gap   *int64 `json:"gap"`
	Runs  int    `json:"runs"`
}

func measure(parser cron.Parser, req request) (result answer) {
	// robfig panics on some malformed values (a TZ= prefix with no schedule); go-cron then never schedules.
	defer func() {
		if failure := recover(); failure != nil {
			result = answer{Error: "parser panic"}
		}
	}()
	schedule, err := parser.Parse(req.Schedule)
	if err != nil {
		return answer{Error: err.Error()}
	}
	day, err := time.Parse("2006-01-02", req.Start)
	if err != nil {
		panic(err)
	}
	loc := time.Local
	if spec, ok := schedule.(*cron.SpecSchedule); ok {
		loc = spec.Location
	}
	first := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, loc)
	end := first.AddDate(0, 0, req.Days)
	moment := first.Add(-time.Nanosecond)
	var gap *int64
	var previous time.Time
	runs := 0
	for {
		next := schedule.Next(moment)
		if next.IsZero() {
			if runs == 0 {
				return answer{Error: "never runs"}
			}
			break
		}
		local := next.In(loc)
		if !time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc).Before(end) {
			break
		}
		if runs > 0 {
			seconds := int64(next.Sub(previous) / time.Second)
			if gap == nil || seconds > *gap {
				gap = &seconds
			}
		}
		previous, moment, runs = next, next, runs+1
	}
	return answer{Gap: gap, Runs: runs}
}

func main() {
	parser := cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			panic(err)
		}
		if err := encoder.Encode(measure(parser, req)); err != nil {
			panic(err)
		}
	}
}
