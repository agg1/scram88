# scram88
scram88 polymorphic scrambler matrix crypto stack

The random number generator implemented as both kernel module and linux core random.c
yields 20GB/s on a 10year old Xeon x5670. The RNG passes FIPS140 rngtest on all interfaces easily:
dd if=/dev/random bs=20000 | rngtest -c 1000
dd if=/dev/urandom bs=20000 | rngtest -c 1000
dd if=/dev/scrandom bs=20000 | rngtest -c 1000

scram88lite symmetric block cipher and scrash88lite scrambler hash are both patched to comply with common
restrictions applied to all publicly available crypto. Nonetheless commercial versions are readily available.
See the scram88lite.c and scrash88lite.c for details regarding limitations and design goals of this cipher and hash.
