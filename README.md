<b>Selection of Hash functions coded in C</b>

Specifically intended for 8-bit microcontrollers, hence optimised for speed assuming
8-bit shifts and very low RAM impact.  Will likely be inefficient on e.g. 32 bit machines.

For instance, when shift is of fixed width known in advance, uses this knowledge to
only act on certain bytes rather than whole 32 bit word.

Extensively tested natively on Atmel microcontroller (100,000+ random hashes each)
compared with same hash calculated in python using hashlib.  Used LFSR to
generate hashes from 0 to 1499 pseudo random characters and transmitted
the LFSR start point, length, and result over the network.

Testing checked for false positives by e.g. setting one byte of hash to arbitrary value
and observing that only c.1/256 now match.

However tested using Little endian ATMega328P.  Big endian version not tested.