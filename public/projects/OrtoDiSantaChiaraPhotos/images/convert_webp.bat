for %%i in (*.jpg) do ffmpeg -i "%%i" -vf scale="iw/3:ih/3" -quality 90 "%%~ni.webp"
pause