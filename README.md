# scram88

## scram88 polymorphic scrambler matrix crypto stack
The random number generator implemented as both kernel module and linux core random.c
yields 20GB/s on a 10year old Xeon x5670. The RNG passes FIPS140 rngtest on all interfaces easily:
dd if=/dev/random bs=20000 | rngtest -c 1000;

dd if=/dev/urandom bs=20000 | rngtest -c 1000;

dd if=/dev/scrandom bs=20000 | rngtest -c 1000;

## cryptographically unbreakable symmetric block cipher
See the scram88lite.c and scrash88lite.c for details regarding limitations and design goals of the cipher and hash.
The symmetric block cipher is 10x faster and more efficient than any other publicly available symmetric block cipher.
It is not prone to any type of cryptoanalysis, involving known-plaintext attacks in particular.
Please see scram88lite.c and scrash88lite.c for details regarding limitations and design goals of this cipher and hash.

## export restrictions
scram88lite symmetric block cipher and scrash88lite scrambler hash are both patched to comply with common
restrictions applied to all publicly available crypto. Nonetheless commercial versions are readily available.

## publication
The publication of the high efficiency unbreakably block cipher was announced on freenode.org IRC 6th September 2019.
A scientist from Leibniz Institute for mathematics and computer science,
funded by German Federal Ministry of Education and Research, responded and the conversation protocol is attached.
To summarize that conversation briefly: even if funded with $20000 - $200000 it wouldn't be possible to break the cipher.
And whatever additional funding it is impossible to break the cipher cryptographically,
while it is 10 times faster and more efficient than any other publicly available crypto funded with millions of Euros.
