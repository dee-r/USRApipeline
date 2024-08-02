#!/bin/bash

set -x

# Check if a directory is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

DIRECTORY=$1

# Process each .argus file in the directory
for file in "$DIRECTORY"/*.argus; do
    # Extract the base name of the file (without extension)
    base_name=$(basename "$file" .argus)

    # Convert Argus data to CSV
    if ! ra -r "$file" > "$DIRECTORY/${base_name}_intermediate1.csv"; then
        echo "Error processing $file with ra command"
        continue
    fi

    # Separate fixed-width Argus columns into comma-separated values
    if ! awk -v OFS=, '{
        print substr($0, 4, 15), substr($0, 21, 8), substr($0, 31, 5),
        substr($0, 37, 18), substr($0, 56, 6), substr($0, 65, 3),
        substr($0, 69, 18), substr($0, 88, 6), substr($0, 96, 7),
        substr($0, 106, 8), substr($0, 115, 5)
    }' "$DIRECTORY/${base_name}_intermediate1.csv" > "$DIRECTORY/${base_name}_intermediate2.csv"; then
        echo "Error processing $file with awk command"
        continue
    fi

    # Remove extra spaces from the CSV
    if ! tr -d ' ' < "$DIRECTORY/${base_name}_intermediate2.csv" > "$DIRECTORY/${base_name}_intermediate3.csv"; then
        echo "Error processing $file with tr command"
        continue
    fi

    # Fix the 'State' column values ending up in the 'TotBytes' column
    if ! awk -F, '{
        if ($(NF) == "" && $(NF-1) != "") {
            for (i=1; i<=NF-2; i++) printf("%s,", $i);
            printf(",%s\n", $(NF-1));
        } else {
            print $0;
        }
    }' "$DIRECTORY/${base_name}_intermediate3.csv" > "$DIRECTORY/${base_name}.csv"; then
        echo "Error processing $file with final awk command"
        continue
    fi

    # Clean up intermediate files
    rm "$DIRECTORY/${base_name}_intermediate1.csv" "$DIRECTORY/${base_name}_intermediate2.csv" "$DIRECTORY/${base_name}_intermediate3.csv"

    echo "Processing complete for $file. Output written to $DIRECTORY/$base_name.csv."
done

echo "All files processed."
