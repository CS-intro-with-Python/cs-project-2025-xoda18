#!/usr/bin/env bash

for i in {1..10}; do
  echo "Attempt $i"
  if python3 client.py; then
    echo "Client succeeded"
    exit 0
  fi
  echo "Server not ready, waiting..."
  sleep 1
done

echo "Client failed"
exit 1
