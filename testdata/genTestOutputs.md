The existing test cases are generated with the `gen.sh` script found in this same folder.

The outputs can be re-generated deterministically again with:
- `random.txt`: `./gen.sh 7 30 random > random.txt`
- `zero.txt`: `./gen.sh 7 10 zero > zero.txt`
- `0xCC.txt`: `./gen.sh 7 10 0xCC >  0xCC.txt`
 
This script assumes that:
- You're running Lotus v1.5.2.
- The `ClientCalcCommP` API needs to be edited a bit to remove CAR header validation since this is random data.
- You have `github.com/jbenet/go-random` in your $PATH.
