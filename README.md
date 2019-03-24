<b>A selection of Hash functions coded in C</b>

Specifically intended for 8-bit microcontrollers, hence optimised primarily for speed 
(assuming 8 bit architecture) and very low RAM impact with code size a further factor.
Will likely be inefficient on e.g. 32 bit machines.

For instance, when shift is of fixed width known in advance, uses this knowledge to
only act on certain bytes rather than whole 32 bit word.

<b>Overall</b>

Of this set and specific implementation, MD5 has lowest code size and is quickest.
However MD5's security is relatively weak.

SHA-1 and SHA-256 have almost identical speed, with SHA-1 having larger code size and 
lower security.  Hence SHA-256 preferred.  SHA-1 does however use less RAM.

RIPEMD-160 is slower than the SHA implementations and larger than SHA-256 (code and RAM)

The reason SHA-256 has less code is because its algorithm is more consistent across 
different rounds.

<b>Testing</b>

Extensively tested natively on Atmel microcontroller (100,000+ random hashes each)
compared with same hash calculated in python using hashlib.  Used LFSR to
generate hashes from 0 to 1499 pseudo random characters and transmitted
the LFSR start point, length, and result over the network.

For subset of above, calculate hash of message repeated 500 times.  i.e. largest 
is c. 1,500x500 characters, i.e. 750,000 characters and test versus Python result.

Testing checked for false positives by e.g. setting one byte of hash to arbitrary value
and observing that only c.1/256 now match.

However tested using Little endian ATMega328P.  Big endian version not tested.