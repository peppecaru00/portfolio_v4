for %%i in (*.jpg) do ffmpeg -i "%%i" -vf scale="1080:1920" -quality 94 "%%~ni.webp"
pause