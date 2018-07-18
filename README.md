# HasPwn

A Tool for playing around with the Pwned Passwords list from Troy Hunt's https://haveibeenpwned.com.

Also, a nice way to teach myself the Go language, doing stupid mistakes, writing non-idiomatic code, and
making a lot of really stupid blunders performance-wise. Hopefully getting wiser from it.

Might eventually evolve into something useful, but for now it's mostly a playground.

## Format of input file

The text version of the password hash list consists of fixed-length lines, formatted as:
SHA-1 as 40 hex chars, 1 char colon delimiter, 20 chars space-padded "number of hits" ascii decimal, \r\n.

## Current ideas

First goal is handling the (sort-by-hash) pwned-passwords-ordered-2.0.txt file, and being able to do something
useful with it. Treat it as a journey, starting with naïve code and linear search, evolving from that.

Plenty of things to consider. The input is sorted, so a few iterations from now, the plan is to do binary
search instead of a linear scan. Before getting there, do a few optimizations of the linear scan, and get
familiar with the Go profiling tools.

After hacking in buffered reading, encoding/hexDecode is responsible for 33% of the runtime. Next iteration:
getting rid repeated calls to hexDecode when dealing with the text version of the password hashes.

Current linear scan is *slow*, since we're doing raw file I/O without buffering. That's a lot of time wasted
doing kernel/usermode transition on syscalls. Next up is adding buffered reading. When implementing binary
search, we probably non-buffered I/O?

A related issue is text vs binary. An interesting addition to this tool is converting the text input to binary
output - there's a *lot* of disk space to be saved. At the obvious level, there's a file-handling interface to
be extracted, something that has at least `getNumRecords` and `getRecord(num)` methods. Those are easy to
extract in text vs binary interfaces, but perhaps there's a larger structure to extract - something that could
handle buffered-scanning vs unbuffered-search.

## Optimizations ideas

Don't return a `hashEntry` but pass a hashEntry pointer to `getRecord`. Allocate before loop, might save
work and garbage collection. Profile.

Differentiate text and binary file inputs. Don't convert text input to binary hash, compare the ascii
representations of hash instead, to avoid wasting cycles. How do we represent this nicely in code? 
Overhead of converting from record to internal rep. is probably only going to matter for linear search
scenario, but it's nice to think of the code structure required to handle this cleanly.

How to instantiate text vs binary interfaces? Trying the {text, binary} implementations in turn? Manual
instantiation based on commandline flags?

Current speed: benchmark limited to 2.5mil hashes.
    `getEntryAt`: 11.89s
    `getNextEntry`: 8.36s
    `getNextEntry`, buffered: 1.98s

## Authors

* **Sune Marcher** - [snemarch](https://github.com/snemarch)

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE.md](LICENSE.md) file for details.
