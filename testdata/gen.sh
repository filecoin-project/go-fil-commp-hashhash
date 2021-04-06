#!/bin/bash
set -euo pipefail

SUFFIX=${3:-random}

seq $1 $2 |
while read exp; 
do
  echo $((3*2**$exp/4));
  echo $((2**$exp*127/128-1));
  echo $((2**$exp*127/128));
  echo $((2**$exp*127/128+1));
  echo $((2**$exp));
done | sort -n | uniq -u |
while read SIZE
do
 FILE=${SIZE}_$SUFFIX.out
 if [ $SUFFIX = "random" ]
 then
   random $SIZE 1337 > $FILE
 elif [ $SUFFIX = "zero" ]
 then
   dd if=/dev/zero bs=1 count=$SIZE status=none > $FILE
 elif [ $SUFFIX = "0xCC" ]
 then
   dd if=/dev/zero bs=1 count=$SIZE status=none | sed 's/\x00/\xCC/g' > $FILE
 fi

 RES=`curl -s -X POST \
	 -H "Content-Type: application/json" \
	 -H "Authorization: Bearer $(cat $LOTUS_PATH/token)" \
	 --data "{ \"jsonrpc\": \"2.0\", \"method\": \"Filecoin.ClientCalcCommP\", \"params\": [\"$(pwd)/$FILE\"], \"id\": 1 }" \
	 'http://127.0.0.1:1234/rpc/v0'`
 UNPADDED_SIZE=`echo $RES | jq .result.Size`
 PADDED_SIZE=$(($UNPADDED_SIZE * 128/127))
 PIECECID=`echo $RES | jq -r .result.Root.\"/\"`
 echo "$SIZE,$PADDED_SIZE,$PIECECID"
 rm $FILE
done

