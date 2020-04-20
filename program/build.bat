@echo off
echo "Building with CL..."

cl.exe main.c tools.c /Feprogram.exe

echo "Build done!"
