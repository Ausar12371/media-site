@echo off
cd /d %~dp0
echo 启动私人媒体站...
echo 正在打开浏览器（已启用自动播放）...
start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --autoplay-policy=no-user-gesture-required --user-data-dir="%~dp0edge-profile" "http://127.0.0.1:8899/login"
.venv\Scripts\python.exe app.py
pause
