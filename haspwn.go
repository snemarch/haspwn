// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package main

import (
	"flag"
	"fmt"

	"github.com/pkg/profile"
	"github.com/snemarch/haspwn/pwnhashes"
)

const benchmarkMaxIter = 100000000

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getProfiler(b string) func(*profile.Profile) {
	switch b {
	case "cpu":
		return profile.CPUProfile
	case "mem":
		return profile.MemProfile
	}

	return nil
}

func getMatcher(base pwnhashes.HashBase, searchType, searchTerm string) pwnhashes.HashHolder {
	switch searchType {
	case "password":
		return base.NewPasswordHolder(searchTerm)
	case "hash":
		return base.NewHashHolder(searchTerm)
	}
	return nil
}

func main() {
	profileType := flag.String("profile", "", "enable profiling, mem or cpu")
	databasePath := flag.String("database", "d:/pwned-passwords-ordered-2.0.txt", "path to hash database")
	searchType := flag.String("format", "password", "format to search for, password or hash")
	searchTerm := flag.String("term", "password", "search term")

	flag.Parse()

	if ptype := getProfiler(*profileType); ptype != nil {
		defer profile.Start(profile.ProfilePath("."), ptype).Stop()
	}

	hashes, err := pwnhashes.Open(*databasePath)
	check(err)
	defer hashes.Close()

	fmt.Printf("File contains %d records\n", hashes.HashCount())

	matcher := getMatcher(hashes, *searchType, *searchTerm)
	// matcher := hashes.NewHashHolder("FFFFFFFEE791CBAC0F6305CAF0CEE06BBE131160") // last hash in database
	// matcher := hashes.NewHashHolder("3333333333333333333333333333333333333333") // test for early-out

	fmt.Printf("Searching for %s\n", matcher.String())
	hashes.Visit(func(hash pwnhashes.HashEntry, index int) bool {
		if (index % 100000) == 0 {
			fmt.Printf("\rChecking hash #%d", index)
		}

		match := hash.Match(matcher)
		switch {
		case match == 0:
			fmt.Printf("\nFound hash, %d occurences\n", hash.Count())
			return false

		case match > 0:
			fmt.Printf("\nhash %s > %s\n", hash, matcher)
			return false

		case index > benchmarkMaxIter:
			if *profileType != "" {
				fmt.Printf("\nExiting for profiling reasons\n")
				return false
			}
		}

		return true
	})
}
