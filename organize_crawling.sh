#!/bin/bash

# Main
INPUT_FILE="crawling.txt"

OUTPUT_DIR="OCR"

mkdir -p "$OUTPUT_DIR"


# Params
grep -aF "?" "$INPUT_FILE" > "$OUTPUT_DIR/crawling_params.txt"

for i in $(cat tools/payloads/parameters.txt); do grep -E "\?$i=|\&$i=" $OUTPUT_DIR/crawling_params.txt >> $OUTPUT_DIR/ps.txt ;done

rm $OUTPUT_DIR/crawling_params.txt

mv $OUTPUT_DIR/ps.txt $OUTPUT_DIR/crawling_params.txt


# Files
grep -avF "?" "$INPUT_FILE" > "$OUTPUT_DIR/temp_no_params.txt" 

extensions=($(grep -aoE "\.[a-zA-Z0-9]+$" "$OUTPUT_DIR/temp_no_params.txt" | sort -u))

if [ ${#extensions[@]} -gt 0 ]; then
 for i in "${extensions[@]}"; do
  if [ "$i" != ".com" ]; then
   clean_name=$(echo "$i" | tr -d '.')
   grep -a "${i}$" "$OUTPUT_DIR/temp_no_params.txt" >> "$OUTPUT_DIR/paths_${clean_name}.txt"
  fi
 done
fi


# Paths
grep -avE "\.[a-zA-Z0-9]+$" "$OUTPUT_DIR/temp_no_params.txt" > "$OUTPUT_DIR/crawling_paths.txt"

rm -f "$OUTPUT_DIR/temp_no_params.txt"

for i in $(cat tools/payloads/catchdirs.txt); do grep "/$i" $OUTPUT_DIR/crawling_paths.txt >> $OUTPUT_DIR/paths.txt ;done

echo "" >  $OUTPUT_DIR/crawling_paths.txt

cat $OUTPUT_DIR/paths.txt | httpx >> $OUTPUT_DIR/crawling_paths.txt 

rm $OUTPUT_DIR/paths.txt



