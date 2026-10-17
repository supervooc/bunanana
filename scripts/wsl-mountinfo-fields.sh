#!/bin/bash
# Show the exact field layout of every mount view the detector compares.
for f in /proc/mounts /proc/self/mountinfo /proc/1/mountinfo /proc/self/mountstats; do
  echo "================ $f ================"
  head -2 "$f"
  echo "--- awk field dump (line 1) ---"
  head -1 "$f" | awk '{ for (i=1;i<=NF && i<=8;i++) printf "  field[%d]=%s\n", i-1, $i }'
done
