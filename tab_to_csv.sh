#!/bin/bash

# Check if an input directory is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <input_directory>"
  exit 1
fi

# Directory containing tab-separated .txt files
INPUT_DIR="$1"
# Directory to save comma-separated .csv files
OUTPUT_DIR="$1"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Loop through all .txt files in the input directory
for txt_file in "$INPUT_DIR"/*.txt; do
  # Get the base name of the file (without directory and extension)
  base_name=$(basename "$txt_file" .txt)
  # Define the output CSV file path
  csv_file="$OUTPUT_DIR/$base_name.csv"
  # Convert tab-separated .txt to comma-separated .csv
  sed -e 's/,/;/g' -e 's/\t/,/g' "$txt_file" > "$csv_file"
  rm "$txt_file"
  echo "Converted $txt_file to $csv_file"
done

echo "All files have been converted."
