#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <input_directory>"
  exit 1
fi


FILEPATH="$1" # path to input logs directory
OUTPATH="$1" # path to output logs directory

echo "Transforming to csv ..."
for log in "$FILEPATH"*.log; do
    # Check if there are no .log files
    if [ "$log" == "$FILEPATH*.log" ]; then
        echo "No .log files found in $FILEPATH"
        break
    fi

    FILEIN=$log
    # Extract the filename without the directory path
    log=$(basename "$log")
    # Change the output file extension from .log to .csv
    FILEOUT=$OUTPATH${log%.log}.csv

    # include -d option in zeek-cut to convert time values into
    # human-readable format. %Y-%m-%dTH%:%M:%S
     cat $FILEIN | zeek-cut -c > $FILEOUT

    # If you don´t want to use zeek-cut, comment the line above
    # and uncomment the line below
    # sed -i '$d' $FILEOUT

    # Remove line 8
    sed -i '8d' $FILEOUT

    # Remove lines 1 to 6
    sed -i '1,6d' $FILEOUT

    # Delete #fields
    sed -i 's/#fields\t//' $FILEOUT

    # Replace ',' with ';'
    sed -i 's/,/;/g' $FILEOUT

    # Replace '\t' with ','
    sed -i 's/\t/,/g' $FILEOUT

done
echo "Done"
