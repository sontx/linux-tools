#include <stdio.h>
#include <memory.h>
#include "aes.h"

#define AES_KEY_SIZE        16 /* 128 bit */
#define AES_KEY_PADDING     3
#define AES_KEY_MINLEN      6
#define ARG_DECODE_MODE     "-d"
#define ARG_DECODE_DEL_MODE "-dD"
#define ARG_ENCODE_MODE     "-e"
#define ARG_ENCODE_DEL_MODE "-eD"
#define ARG_HELP_MODE       "-h"

typedef void (*crypt_method)(const BYTE*, BYTE*, const WORD*, int);

bool valid_key(const char* user_key, WORD* out_key)
{
    size_t init_len = strlen(user_key);
    if(init_len < AES_KEY_MINLEN || init_len > AES_KEY_SIZE)
        return false;
    BYTE* buff = new BYTE[AES_KEY_SIZE];
    memset(buff, AES_KEY_PADDING, AES_KEY_SIZE);
    int copy_len = init_len < AES_KEY_SIZE ? init_len : AES_KEY_SIZE;
    memcpy(buff, user_key, copy_len);
    aes_key_setup(buff, out_key, AES_KEY_SIZE * 8);
    delete[] buff;
    return true;
}

void e(const char* st)
{
    int len = strlen(st);
    char* buff = new char[len + 2];
    memcpy(buff, st, len);
    buff[len] = '\n';
    buff[len + 1] = '\0';
    fputs(buff, stderr);
    delete[] buff;
}

void i(const char* st)
{
    printf("%s\n", st);
}

bool erase_file(const char* fn)
{
    FILE* out;
    if((out = fopen(fn, "wb")) == NULL)
        return false;
    fseek(out , 0 , SEEK_END);
    long length = ftell(out);
    rewind(out);
    BYTE zero = 0;
    for(register long i = 0; i < length; ++i)
    {
        fwrite(&zero, 1, 1, out);
    }
    fclose(out);
    return remove(fn) == 0;
}

bool process_file(FILE* in,
                  FILE* out,
                  const WORD* key,
                  crypt_method whatdo,
                  void (*callback)(long, int),
                  bool encrypt)
{
    BYTE* in_buff = new BYTE[AES_BLOCK_SIZE];// in
    BYTE* out_buff = new BYTE[AES_BLOCK_SIZE];// out
    size_t read_len, write_len, require_write_len = AES_BLOCK_SIZE;
    bool ok = true;
    long processed = 0;
    // get total length of input file
    fseek(in , 0 , SEEK_END);
    long out_size = ftell(in);
    if(out_size % 16)
        out_size += AES_BLOCK_SIZE - out_size % 16;
    rewind (in);

    for(;processed < out_size;)
    {
        // read data block from input file
        memset(in_buff, EOF, AES_BLOCK_SIZE);
        read_len = fread(in_buff, 1, AES_BLOCK_SIZE, in);
        // check for error
        if(read_len == 0)
            break;
        if(read_len != AES_BLOCK_SIZE && ferror(in))
        {
            e("Reading error occurred");
            ok = false;
            break;
        }
        // encode/decode data block
        whatdo(in_buff, out_buff, key, AES_KEY_SIZE * 8);
        // write to output file
        if(!encrypt && (processed + AES_BLOCK_SIZE == out_size))
        {
            for(int i = AES_BLOCK_SIZE - 1; i > -1; i--)
            {
                if(out_buff[i] == (BYTE)EOF)
                {
                    require_write_len = i;
                    break;
                }
            }
        }
        write_len = fwrite(out_buff, 1, require_write_len, out);
        // check for write error
        if(write_len != require_write_len && ferror(out))
        {
            e("Writing error occurred");
            ok = false;
            break;
        }
        // call callback function for update process
        processed += read_len;
        if(callback != NULL)
            callback(out_size, processed);
    }

    // release memory
    delete[] in_buff;
    delete[] out_buff;
    if(ok && callback != NULL)
        callback(out_size, out_size);
    return ok;
}

void prog()
{
    printf("UNBOX v1.0\n");
    printf("Dev by NE, 11-2015\n");
    printf("Encrypt or decrypt your file with secret password.\n\n");
}

void help_mode()
{
    printf("Usage: unbox mode src des password\n");
    printf("Mode:\n");
    printf("  %s \t encrypt [src] file to [des] file.\n", ARG_ENCODE_MODE);
    printf("  %s \t encrypt [src] file to [des] file and delete [src] file when done.\n", ARG_ENCODE_DEL_MODE);
    printf("  %s \t decrypt [src] file to [des] file.\n", ARG_DECODE_MODE);
    printf("  %s \t decrypt [src] file to [des] file and delete [src] file when done.\n", ARG_DECODE_DEL_MODE);
    printf("Src: source file which will be read to encrypt/decrypt.\n");
    printf("Des: target file which will be write new data.\n");
    printf("Password: a secret key use to encrypt/decrypt file.\n");
    printf("\nExample: unbox %s \"/home/src_file.txt\" \"/home/des_file.txt\" mypassword\n", ARG_ENCODE_MODE);
    printf("This command will encrypt src_file.txt with secret password is mypassowrd then write to des_file.txt\n");
}

void processed_callback(long total, int processed)
{
    static int last = 0;
    int percent = processed / (double) total * 100.0f;
    if(percent > last)
    {
        last = percent;
        if(percent < 100)
            printf("%d\%\n\033[F", percent);
        else
            printf("%d\%\n",  percent);
    }
}

void work_mode(const char* mode,
               const char* src,
               const char* des,
               const char* password)
{
    bool require_delete = false;
    crypt_method whatdo = NULL;

    // decode
    if(strcmp(mode, ARG_DECODE_MODE) == 0)
    {
        i("Decrypt mode.");
        whatdo = aes_decrypt;
    }
    // decode and delete src
    else if(strcmp(mode, ARG_DECODE_DEL_MODE) == 0)
    {
        i("Decrypt with delete mode.");
        require_delete = true;
        whatdo = aes_decrypt;
    }
    // encode
    else if(strcmp(mode, ARG_ENCODE_MODE) == 0)
    {
        i("Encrypt mode.");
        whatdo = aes_encrypt;
    }
    // encode and delete src
    else if(strcmp(mode, ARG_ENCODE_DEL_MODE) == 0)
    {
        i("Encrypt with delete mode.");
        require_delete = true;
        whatdo = aes_encrypt;
    }
    else
    {
        e("Wrong mode! use -h to see more.");
        return;
    }

    // open files, prepare for data io
    FILE* in;
    FILE* out;
    if((in = fopen(src, "rb")) == NULL)
    {
        e("Src file can not open for read!");
        return;
    }
    if((out = fopen(des, "wb")) == NULL)
    {
        e("Des file can not open for write!");
        return;
    }

    // valid password
    WORD key[AES_BLOCK_KEYOUT_SIZE128];
    if(!valid_key(password, key))
    {
        e("Your password must have length greater or equal 6");
        fclose(in);
        fclose(out);
        return;
    }

    // now! process file
    i("Processing...");
    bool ok = process_file(in, out, key, whatdo, processed_callback, whatdo == aes_encrypt);
    i("Processed!");
    fclose(in);
    fclose(out);
    if(ok)
    {
        if(require_delete)
        {
            i("Deleting src file...");
            if(erase_file(src))
                e("Can not delete src file!");
            else
                i("Deleted!");
        }
        i("Done!");
    }
    else
    {
        remove(des);
    }
}

int main(int argc, char *argv[])
{
    prog();
    if(argc == 2)
    {
        if(strcmp(argv[1], ARG_HELP_MODE) != 0)
            e("Wrong mode param!");
        help_mode();
    }
    else if(argc == 5)
    {
        work_mode(argv[1], argv[2], argv[3], argv[4]);
    }
    else
    {
        e("Wrong param!");
        help_mode();
    }

    return(0);
}
