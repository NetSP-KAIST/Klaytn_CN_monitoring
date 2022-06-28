#!/bin/sh

cDir=$(pwd)/SecData

echo $cDir

while : 
do
   count=$(ls -la $cDir | wc -l)
   threshold=3
   timestamp=$(date +%Y-%m-%d-%H-%M-%S)
   
   for file in $cDir/*; do
      if [ $count -gt $threshold ]; then
         echo "${file##*/}" "$timestamp"
         scp $cDir/${file##*/} {host_machine user}@{host machine IP}:~/secrets/
         rm $cDir/${file##*/}
      fi
   done
done


