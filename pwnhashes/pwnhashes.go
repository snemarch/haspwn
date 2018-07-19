// Package pwnhashes provides
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package pwnhashes

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// HashHolder holds the hash to search for, with implementations choosing the most suitable representation.
type HashHolder interface {
	Binary() [20]byte
	String() string
}

type hashMatcherText struct {
	hash string
}

func (match *hashMatcherText) Binary() [20]byte {
	binhash, _ := hex.DecodeString(match.hash)
	var result [20]byte
	copy(result[:], binhash)
	return result
}

func (match *hashMatcherText) String() string {
	return match.hash
}

type hashEntryText struct {
	hash  [40]byte
	count [20]byte
}

// HashEntry is an entry from the hash database
type HashEntry interface {
	Match(HashHolder) int
	String() string
	Count() int64
}

func (hash *hashEntryText) Match(m HashHolder) int {
	return strings.Compare(string(hash.hash[:]), m.String())
}

func (hash *hashEntryText) String() string {
	return string(hash.hash[:])
}

func (hash *hashEntryText) Count() int64 {
	scount := strings.TrimSpace(string(hash.count[:]))
	count, _ := strconv.ParseInt(scount, 10, 64)
	return count
}

// HashBase is a database of hashes
type HashBase interface {
	// NewHashHolder constructs a HashHolder from a hex-encoded hash string
	NewHashHolder(hexHash string) HashHolder

	// NewPasswordHolder constructs a HashHolder from the SHA-1 of supplied password
	NewPasswordHolder(password string) HashHolder

	// Visit iterates over all hashes, calling the visitor function for each
	// entry. The Visitor receives hashentry and index, must return true to
	// continue visiting or false to abort
	Visit(func(HashEntry, int) bool)

	// HashCount returns the number of hashes in the database
	HashCount() int

	// Close closes the underlying file
	Close()

	recordSize() int
}

type hashBaseText struct {
	count int
	file  *os.File
}

func (base *hashBaseText) NewHashHolder(hexHash string) HashHolder {
	return &hashMatcherText{hash: hexHash}
}

func (base *hashBaseText) NewPasswordHolder(hexHash string) HashHolder {
	hash := sha1.Sum([]byte(hexHash))
	hexhash := hex.EncodeToString(hash[:])

	return &hashMatcherText{hash: hexhash}
}

func (base *hashBaseText) Visit(visitor func(HashEntry, int) bool) {
	bf := bufio.NewReaderSize(base.file, base.recordSize()*1000)
	for i := 0; i < base.HashCount(); i++ {
		buf := make([]byte, base.recordSize())
		read, err := bf.Read(buf)
		if err != nil {
			return
		}
		if read != base.recordSize() {
			return
		}

		entry := hashEntryText{}
		copy(entry.hash[:], buf[:40])
		copy(entry.count[:], buf[41:61])

		if !visitor(&entry, i) {
			break
		}
	}
}

func (base *hashBaseText) HashCount() int {
	return base.count
}

func (base *hashBaseText) Close() {
	base.file.Close()
}

func (base *hashBaseText) recordSize() int {
	return 63
}

// Open creates a new hash database instance from existing file
func Open(filename string) (HashBase, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if err != nil {
		return nil, err
	}

	switch {
	case s.Size()%63 == 0:
		return &hashBaseText{file: f, count: int(s.Size() / 63)}, nil

	case s.Size()%28 == 0:
		return nil, fmt.Errorf("binary hashbase not implemented yet")

	default:
		return nil, fmt.Errorf("file size doesn't match known format")
	}
}
