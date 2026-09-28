#!/bin/bash

for i in *.jpg; do
    # Check if files exist to prevent errors if no .jpg files are found
    [ -e "$i" ] || continue
    
    ffmpeg -i "$i" -vf scale="1080:1920" -quality 99 "${i%.jpg}.webp"
done

read -p "Press [Enter] to continue..."
