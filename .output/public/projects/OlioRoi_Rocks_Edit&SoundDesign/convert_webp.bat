for %%i in (*.png) do ffmpeg -i "%%i" -vf scale="iw/2:ih/2" -quality 90 "%%~ni.webp"
pause