#include <stdio.h>
#include <stdlib.h>

long getFileSize(FILE* file) {
    long fileSize = -1;
    if (file != NULL) {
        if (fseek(file, 0L, SEEK_END) == 0) {
            fileSize = ftell(file);
        }
        rewind(file);
    }
    return fileSize;
}

#define KEY 14


int main()
{
    FILE *fp = NULL;
    
    fp = fopen("x64/Release/LRM.sys", "r");
    long sz = getFileSize(fp);
    char* buff = malloc(sz);//100k
    fread(buff, sz, 1, fp);
    //fread()
    fclose(fp);
    printf("File Size: %ld\n", sz);
    //encrypt
    for (int i = 0;i < sz; i++){
        buff[i] ^= (i + KEY) % 256;
    }
    fp = fopen("x64/Release/LRM.sys.enc", "w");
    fwrite(buff, sz, 1, fp);
    fclose(fp);


}