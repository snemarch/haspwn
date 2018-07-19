// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package main

import (
	"fmt"

	"github.com/pkg/profile"
	"github.com/snemarch/haspwn/pwnhashes"
)

const benchmarkMaxIter = 2500000

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	defer profile.Start(profile.ProfilePath(".")).Stop()

	const databasePath = "d:/pwned-passwords-ordered-2.0.txt"
	const passwordToFind = "password"

	hashes, err := pwnhashes.Open(databasePath)
	check(err)
	defer hashes.Close()

	fmt.Printf("File contains %d records\n", hashes.HashCount())

	matcher := hashes.NewPasswordHolder(passwordToFind)

	fmt.Printf("Searching for %s\n", matcher.String())
	hashes.Visit(func(hash pwnhashes.HashEntry, index int) bool {
		if (index % 100000) == 0 {
			fmt.Printf("\rChecking hash #%d", index)
		}

		match := hash.Match(matcher)
		switch {
		case index > benchmarkMaxIter:
			fmt.Printf("\nExiting for profiling reasons\n")
			return false

		case match == 0:
			fmt.Printf("\nFound hash, %d occurences\n", hash.Count())
			return false

		case match > 1:
			fmt.Printf("\nhash %s > %s\n", hash, matcher)
			return false
		}

		return true
	})
}
