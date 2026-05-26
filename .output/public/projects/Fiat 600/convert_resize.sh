#!/bin/bash

# Create a webp_converted folder to keep things organized
mkdir -p webp_converted

# Loop through common image extensions (case insensitive)
shopt -s nocaseglob
for f in *.{jpg,jpeg,png,tiff,bmp}; do
  # Check if file exists to avoid 'no match' errors
  [ -e "$f" ] || continue
  
  # Remove the extension from the filename
  filename="${f%.*}"
  
  echo "🚀 Converting: $f"
  
  # ffmpeg conversion:
  # -i: input file
  # -q 80: sets quality (0-100, 75 is a sweet spot for size/quality)
  # -preset photo: optimizes for photography
  ffmpeg -i "$f" -q:v 80 -vf scale="iw/2:ih/2" -preset photo "webp_converted/${filename}.webp" -hide_banner -loglevel error
done

echo "✅ All images converted to 'webp_converted/' folder."
