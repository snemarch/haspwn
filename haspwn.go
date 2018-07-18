// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/profile"
)

type hashEntry struct {
	Hash  [20]byte
	Count int64
}

const recordSize = 63
const benchmarkMaxIter = 2500000

func getNextEntry(f *os.File) (*hashEntry, error) {
	buf := make([]byte, recordSize)
	read, err := f.Read(buf)

	return constructEntry(buf, read, err)
}

func getEntryAt(f *os.File, num int64) (*hashEntry, error) {
	buf := make([]byte, recordSize)
	read, err := f.ReadAt(buf, num*int64(recordSize))

	return constructEntry(buf, read, err)
}

func constructEntry(buf []byte, read int, err error) (*hashEntry, error) {
	if err != nil {
		return nil, nil
	}
	if read != recordSize {
		return nil, fmt.Errorf("%d != %d", read, recordSize)
	}

	entry := new(hashEntry)
	read, err = hex.Decode(entry.Hash[:], buf[0:40])

	scount := strings.TrimSpace(string(buf[41:61]))
	count, err := strconv.ParseInt(scount, 10, 64)

	entry.Count = count

	return entry, err
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	defer profile.Start(profile.ProfilePath(".")).Stop()
	const recordSize = 63

	f, err := os.Open("d:/pwned-passwords-ordered-2.0.txt")
	check(err)

	s, err := f.Stat()
	check(err)

	remainder := s.Size() % 63
	if remainder != 0 {
		panic("File size isn't a multiple of 63")
	}

	records := s.Size() / int64(recordSize)
	fmt.Printf("File contains %d records\n", records)

	toFind := sha1.Sum([]byte("password"))
	fmt.Printf("Searching for %s\n", hex.EncodeToString(toFind[:]))

	i := int64(0)
search:
	for i = int64(0); i < records; i++ {
		if (i % 100000) == 0 {
			fmt.Printf("\rChecking hash #%d", i)
		}

		hash, err := getNextEntry(f) // 8.36s for 2.5mil reads
		// hash, err := getEntryAt(f, int64(i)) // 11.89s for 2.5mil reads
		check(err)

		res := bytes.Compare(hash.Hash[:], toFind[:])
		switch {
		case i > benchmarkMaxIter:
			fmt.Printf("Exiting for profiling reasons")
			break search

		case res == 0:
			fmt.Printf("Found hash, %d occurences\n", hash.Count)
			break search

		case res > 1:
			fmt.Printf("hash %s > %s\n",
				hex.EncodeToString(hash.Hash[:]),
				hex.EncodeToString(toFind[:]))
			break search
		}
	}

	fmt.Printf("\n%d hashes searched\n", i)
}
