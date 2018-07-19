# HasPwn

A Tool for playing around with the Pwned Passwords list from Troy Hunt's https://haveibeenpwned.com.

Also, a nice way to teach myself the Go language, doing stupid mistakes, writing non-idiomatic code, and
making a lot of really stupid blunders performance-wise. Hopefully getting wiser from it. And starting out
purposefully naïve, since that'll give some nice, big factors on the first optimization iterations :-)

Might eventually evolve into something useful, but for now it's mostly a playground. Goldplating OK.

## Format of input file

The text version of the password hash list consists of fixed-length lines, formatted as:
SHA-1 as 40 hex chars, 1 char colon delimiter, 20 chars space-padded "number of hits" ascii decimal, \r\n.

## Current ideas

First goal is handling the (sort-by-hash) pwned-passwords-ordered-2.0.txt file, and being able to do something
useful with it. Treat it as a journey, starting with naïve code and linear search, evolving from that.

Plenty of things to consider. The input is sorted, so a few iterations from now, the plan is to do binary
search instead of a linear scan. Before getting there, do a few optimizations of the linear scan, and get
familiar with the Go profiling tools.

An interesting addition to this tool would be converting the text input to binary output - there's a *lot* of
disk space to be saved (reducing file size from 29.43 -> 13.08 gigabytes - or 11.21 if we choose a 32bit int
for breach count). The first iteration of HasPwn had `getNumRecords` and `getRecord(num)` methods, which were
dropped by the re-architectured version in favor of a `Visit` method. A `BinarySearch` probably belongs in
this interface as well, but there's some more re-architecturing needed to get things right; to avoid code
duplication as well as giving a coherent feel.

Probably time to move profiling code out of the main file, and adding a haspwn_test with a benchmark?

## Optimization history

First version: linear scan was *slow*, since we were doing raw file I/O without buffering. That's a lot of
time wasted doing kernel/usermode transition on syscalls. Buffered I/O needed.

After hacking in buffered reading, encoding/hexDecode was responsible for 33% of the runtime. HasPwn was
re-architected with the concept of `HashBase` and `HashHolder` interfaces, the idea being that the `HashBase`
implementation can choose a `HashHolder` implementation that minimizes conversion.

For the first four iterations, the benchmarking was done for 2.5 million hash searches. From iteration five,
this was increased to 100M to have meaningful numbers again.

Speed history:
    iteration 1: `getEntryAt`: 11.89s
    iteration 2: `getNextEntry`: 8.36s
    iteration 3: `getNextEntry`, buffered: 1.98s
    iteration 4: rearchitected: 350ms (25-27s with 100M)
    iteration 5: Visit: buffer allocation outside loop, 20-22s

## Optimizations ideas

Have a thorough look at the data representation - there's bound to be overhead associated with the current
juggling between strings, arrays and slices. And while I like being specific about types and lengths when
they're known, the conversions required for the current data layout feel a bit clunky. Perhaps it's better to
just go "slices, slices, everywhere"?

On SSD and NVMe storage, we should be able to benefit from parallelization - those storage types don't tend to
reach full througput (even if doing raw I/O with no compute) from a single access stream. It seems like a lot
of code complexity to add, considering the goal is binary search which should give sub-second lookup time.
But this project is about learning and gold-plating is OK, so perhaps implement it anyway.

Parallelizing the code poses some interesting issues, especially around how to do the file I/O. I assume the
bufio/Reader isn't written to allow multiple Readers for a single File - and that probably can't be done in a
thread-safe way anyhow, since seek + read isn't atomic. Perhaps several File + Reader instances for the same
underlying file? That, or moving to memory-mapped I/O.

## Authors

* **Sune Marcher** - [snemarch](https://github.com/snemarch)

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE.md](LICENSE.md) file for details.
