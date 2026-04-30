for %%i in (*.jpg) do ffmpeg -i "%%i" -quality 100 "%%~ni.webp"
pause