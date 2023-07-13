#echo -n \#define LRM_BASE64 \" > ../LRMAPP/lrmbin.h
./a.out
xxd -i x64/Release/LRM.sys.enc > ../LRMAPP/lrmbin.h
#echo \" >> ../LRMAPP/lrmbin.h
echo -n // >> ../LRMAPP/lrmbin.h
date >> ../LRMAPP/lrmbin.h