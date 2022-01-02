call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

cd rw && msbuild /property:Configuration=Debug /property:Platform=x64 || exit /b
cd ..
cd rw-drv && msbuild /property:Configuration=Debug /property:Platform=x64 || exit /b
cd ..
cd rw-test && msbuild /property:Configuration=Debug /property:Platform=x64 || exit /b
cd ..

copy rw-drv\x64\Debug\rw-drv.sys C:\Users\luca\Documents\Projects\kdbg-driver-workstation\guest\layle.sys
copy rw\x64\Debug\rw.exe C:\Users\luca\Documents\Projects\kdbg-driver-workstation\guest
copy rw-test\x64\Debug\rw-test.exe C:\Users\luca\Documents\Projects\kdbg-driver-workstation\guest

cd C:\Users\luca\Documents\Projects\kdbg-driver-workstation
.\kdbg.bat