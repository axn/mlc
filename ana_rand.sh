#!/usr/bin/env bash
#
# Generates a random integer in a given range

# computes the ceiling of log2
# i.e., for parameter x returns the lowest integer l such that 2**l >= x
log2() {
  local x=$1 n=1 l=0
  while (( x>n && n>0 ))
  do
    let n*=2 l++
  done
  echo $l
}


# uses $RANDOM to generate an n-bit random bitstring uniformly at random
#  (if we assume $RANDOM is uniformly distributed)
# takes the length n of the bitstring as parameter, n can be up to 60 bits
get_n_rand_bits() {
  local n=$1 rnd=$RANDOM rnd_bitlen=15
  while (( rnd_bitlen < n ))
  do
      rnd=$(( rnd<<15|$RANDOM ))
      let rnd_bitlen+=15
  done
  echo $(( rnd>>(rnd_bitlen-n) ))
}


# alternative implementation of get_n_rand_bits:
# uses /dev/urandom to generate an n-bit random bitstring uniformly at random
#  (if we assume /dev/urandom is uniformly distributed)
# takes the length n of the bitstring as parameter, n can be up to 56 bits
get_n_rand_bits_alt() {
  local n=$1
  local nb_bytes=$(( (n+7)/8 ))
  local rnd=$(od --read-bytes=$nb_bytes --address-radix=n --format=uL /dev/urandom | tr --delete " ")
  echo $(( rnd>>(nb_bytes*8-n) ))
}

# for parameter max, generates an integer in the range {0..max} uniformly at random
# max can be an arbitrary integer, needs not be a power of 2
rand() {
  local rnd max=$1
  # get number of bits needed to represent $max
  local bitlen=$(log2 $((max+1)))
  while
    # could use get_n_rand_bits_alt instead if /dev/urandom is preferred over $RANDOM
    rnd=$(get_n_rand_bits $bitlen)
    (( rnd > max ))
  do :
  done
  echo $rnd
}

# MAIN SCRIPT

# check number of parameters
if (( $# != 1 && $# != 2 ))
then
  cat <<EOF 1>&2
Usage: $(basename $0) [min] max

Returns an integer distributed uniformly at random in the range {min..max}
min defaults to 0
(max - min) can be up to 2**60-1  
EOF
  exit 1
fi

# If we have one parameter, set min to 0 and max to $1
# If we have two parameters, set min to $1 and max to $2
max=0
while (( $# > 0 ))
do
  min=$max
  max=$1
  shift
done

# ensure that min <= max
if (( min > max ))
then
  echo "$(basename $0): error: min is greater than max" 1>&2
  exit 1
fi

# need absolute value of diff since min (and also max) may be negative
diff=$((max-min)) && diff=${diff#-}

echo $(( $(rand $diff) + min ))
