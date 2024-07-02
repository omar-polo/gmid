# Fuzzying gmid

Here are some notes on how to fuzz (some) gmid parts using afl.

 - run `make -C ../../ clean` beforehand so that we compile all relevant
   sources with afl-clang.  Then, clean again before rebuilding gmid.

 - run `make fuzz-iri` to fuzz the IRI parser.

 - run `make fuzz-proto` to fuzz the proxy v1 protocol parser.
