package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sendbeam/cli/internal/updater"
)

const defaultRepo = "Akshay7273/sendbeam"

func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	checkOnly := fs.Bool("check", false, "check for updates without applying")
	channelFlag := fs.String("channel", "stable", "update channel (stable or beta)")
	jsonOutput := fs.Bool("json", false, "format output as JSON")
	repoFlag := fs.String("repo", defaultRepo, "target repository")

	_ = fs.Parse(args)

	ch, err := updater.ParseChannel(*channelFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam update: %v\n", err)
		return 1
	}

	u, err := updater.New(Version, *repoFlag, updater.WithChannel(ch))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam update: initializing updater: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	s := newStyle(os.Stdout)

	if !*jsonOutput {
		fmt.Fprintf(os.Stderr, "Checking for updates (current version: %s, channel: %s)...\n", Version, ch)
	}

	res, err := u.Check(ctx)
	if err != nil {
		if *jsonOutput {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"status": "error",
				"error":  err.Error(),
			})
		} else {
			fmt.Fprintf(os.Stderr, "sendbeam update: check failed: %v\n", err)
		}
		return 1
	}

	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return 0
	}

	if !res.UpdateAvailable {
		fmt.Println(s.green(res.Message))
		return 0
	}

	fmt.Println(s.cyan(res.Message))

	if *checkOnly {
		if res.TargetAsset != nil {
			fmt.Printf("Run %s to install this update.\n", s.bold("sendbeam update"))
		}
		return 0
	}

	fmt.Printf("Downloading and applying %s (%s)...\n", res.LatestVersion, res.TargetAsset.Name)
	if err := u.Apply(ctx, res); err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam update: apply failed: %v\n", err)
		return 1
	}

	fmt.Printf("%s Successfully updated to %s!\n", s.green("✓"), s.bold(res.LatestVersion.String()))
	return 0
}
