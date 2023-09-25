#!/bin/sh

numNodes=4
for i in $(seq 0 $numNodes); do
  docker stack deploy --compose-file "narwhal_primary_${i}.yaml" narwhal &
  docker stack deploy --compose-file "narwhal_worker_${i}.yaml" narwhal &
done