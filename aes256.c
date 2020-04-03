/*
 * Author: Rodrigo Gutiérrez (r.gutierrezc80@gmail.com)
 * AES implementation: https://github.com/kokke/tiny-AES-c
 * Topics covered: File IO, string handling, using 3rd party code
 *
*/

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>

// include encryption header
#include "aes.h"

#define MAX_KEY_SIZE 32 // size in bytes. 32 for AES256, 24 AES192, 16 AES128

// modes
#define ENCRYPTION_MODE 0
#define DECRYPTION_MODE 1
#define UNDEFINED_MODE -1

struct AES_ctx;

off_t fsize(const char *filename) {
    struct stat st; 

    return (stat(filename, &st) == 0 ? st.st_size : -1); 
}

// designed with PKCS7 padding in mind
uint8_t calculate_padding(uint32_t size, uint8_t block) {
	return (size%block==0 ? block : block - (size%block));
}

// both functions from:
// https://stackoverflow.com/questions/4553012/checking-if-a-file-is-a-directory-or-just-a-file
int is_regular_file(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

void getPassword(char password[])
{
    static struct termios oldt, newt;
    int i = 0;
    int c;

    /*saving the old settings of STDIN_FILENO and copy settings for resetting*/
    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;

    /*setting the approriate bit in the termios struct*/
    newt.c_lflag &= ~(ECHO);

    /*setting the new bits*/
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    /*reading the password from the console*/
    while ((c = getchar())!= '\n' && c != EOF && i < MAX_KEY_SIZE){
        password[i++] = c;
    }
    password[i] = '\0';

    /*resetting our old STDIN_FILENO*/ 
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

}

int isDirectory(const char *path) {
   struct stat statbuf;
   if (stat(path, &statbuf) != 0)
       return 0;
   return S_ISDIR(statbuf.st_mode);
}

void processFile(const char* file, int8_t enc_mode, struct AES_ctx* ctx) {
	
	FILE *fp;
	char ch;

	fp = fopen(file, "r"); // read mode
 
	if (fp == NULL)
	{
		perror("Error while opening the file.\n");
		exit(EXIT_FAILURE);
	}
	
	uint32_t total_size=0, file_size = 0;
	uint8_t padding_space=0;

	if (enc_mode==ENCRYPTION_MODE) {
		// adding padding: PKCS7
		padding_space = calculate_padding(fsize(file),AES_BLOCKLEN);
		file_size = fsize(file);
		total_size = fsize(file)+padding_space;	
	} else if (enc_mode==DECRYPTION_MODE){
		// if magic bytes not present, error and exit.
		fseek(fp,-16,SEEK_END);
		char magic_bytes[16];
		for (int i=0;i<16;i++) {
			magic_bytes[i]=fgetc(fp);
		}
		//printf("magic bytes leidos: [%s]\n",magic_bytes);
		if(strcmp(magic_bytes,"b30WuLf_y0u2L02\0")!=0) {
			printf("Not an encrypted file, aborting...\n");
			exit(EXIT_FAILURE);
		}
		fseek(fp,0,SEEK_SET);
		total_size = fsize(file)-16;
		printf("total size calculado es %d\n", total_size);
		
		
	} else {
		printf("Unknown operation mode, something weird is going on. Terminating.\n");
		exit(EXIT_FAILURE);		
	}

	// if we store the array in the stack, we might cause a
	// segmentation fault if the file exceeds the allocated stack size
	// malloc allocates space in the heap, no space problems! (hopefully...)
	uint8_t* in = malloc(total_size);
	
	// max file size is 2^32 bit, > 4TB
	uint32_t x = 0;
	while(x < (enc_mode==ENCRYPTION_MODE ? file_size : total_size)) {
		ch = fgetc(fp);
		in[x++] = ch;
	}
	fclose(fp);
	
	// 	the beauty of PKCS7 lies on its simplicity:
	//	every byte of the padding contains 
	//	the number of padded bytes, so even if the last byte of data
	//	before padding was that same number, we would never remove it
	//	after the file was decrypted
	if (enc_mode==ENCRYPTION_MODE) {
		while (x < total_size) {
			in[x++] = padding_space;
		}
		
		// all data in place, let's move on with encryption
    	AES_CBC_encrypt_buffer(ctx, in, total_size);
    
	} else {
		
		AES_CBC_decrypt_buffer(ctx, in, total_size);
	}
	 
	char dest_path[255];
	strcpy(dest_path, file);
	FILE *f = fopen(dest_path, "w");
	// en in[total_size] -1 tenemos el numero de bytes del padding
	fwrite(in, sizeof(char), (enc_mode==ENCRYPTION_MODE?total_size:total_size-in[total_size-1]), f);
	fclose(f);
	if (enc_mode==ENCRYPTION_MODE) {
		//add magic bytes so we know that its our encrypted file.
		f = fopen(dest_path,"a");
		char* magic_bytes = (char*)malloc(16 * sizeof(uint8_t));
		strcpy(magic_bytes, "b30WuLf_y0u2L02\0");
		fwrite(magic_bytes,sizeof(uint8_t),16, f);
		fclose(f);
	}
}

void processDirEntry(const char* dir_entry, int8_t enc_mode, struct AES_ctx* ctx) {
	if(is_regular_file(dir_entry)) {
		if (enc_mode==ENCRYPTION_MODE)
			printf("Encrypting ");
		else printf("Decrypting ");
		printf("file %s...\n",dir_entry);
		processFile(dir_entry, enc_mode, ctx);
	} else if (isDirectory(dir_entry)) {
		printf("%s is a directory\n",dir_entry);
		
		DIR *d;

    	struct dirent *dir;

    	d = opendir(dir_entry);
    	if (d)
    	{
	        while ((dir = readdir(d)) != NULL)
	        {
	            if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0) {
		            char path[255];
		            strcpy(path, dir_entry);
		            strcat(path, "/");
		            strcat(path, dir->d_name);
		            processDirEntry(path, enc_mode, ctx);
	        	}
	        }
	        closedir(d);
    	} else { printf("Couldn't open %s dir. Check permissions.\n",dir_entry);}
	} else {
		printf("Couldn't open %s.\n", dir_entry);
	}
}



int main(int argc, char **argv) {
	// using AES256 so we need 128 bit key
	// we repeat what we read from keyboard until we get 256 bits
	
    // todo: give option to read all files in folder and subfolders
    // and cypher them
	

	int8_t mode = UNDEFINED_MODE;
	uint8_t mode_index = -1;

	// if not a single argument is given, display usage error
	if (argc < 2 ) {
		printf("Usage: aes256 [-c|-d] [file|dir] [file|dir] ...\n");
		printf("-c : encrypt, -d : decrypt. Folders passed will recursively (de)encrypt all files inside, subfolders included.\n");
		printf("Error: [-c|-d] option is mandatory.\n");
		exit(EXIT_FAILURE);
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-d")==0 ) {
			if ( mode ==UNDEFINED_MODE) {
				mode = DECRYPTION_MODE;
				mode_index = i;
			} else {
				printf("Wrong arguments. Please use either -c or -d once.\n"); 
				exit(EXIT_FAILURE);
			}
		} else if (strcmp(argv[i], "-c")==0) {
			if ( mode ==UNDEFINED_MODE) {
				mode = ENCRYPTION_MODE;
				mode_index = i;
			} else {
				printf("Wrong arguments. Please use either -c or -d once.\n"); 
				exit(EXIT_FAILURE);
			}
		}
	}

	if (mode == UNDEFINED_MODE) {
		printf("Wrong arguments. Please use either -c or -d once.\n"); 
		exit(EXIT_FAILURE);
	}

	// request password from user
	uint8_t key[MAX_KEY_SIZE];
	uint8_t repeat[MAX_KEY_SIZE];
	
	char ch, user_input[512],*p;
	FILE *fp;

	printf("Please input password: ");
	printf("\n");
	getPassword(key);
	printf("Please type it again: ");
	getPassword(repeat);
	if(strcmp(key,repeat)!=0) {
		printf("Passwords did not match, aborting.\n");
		exit(EXIT_FAILURE);
	}
	// fgets(key, MAX_KEY_SIZE, stdin);
	printf("\n");

	printf("The following files and folders will try to be ");
	printf(mode==ENCRYPTION_MODE ? "ENCRYPTED!: " : "DECRYPTED!: ");
	for (int i=1;i<argc;i++) {
		if (i!=mode_index) {
			printf("[%s] ",argv[i]);
		}	
	}
	printf("\nDo you want to continue? [Y/n]: ");
	char reply = getchar();
	if (reply=='Y') {

	} else { exit(EXIT_SUCCESS);};
	
	// find the end of key
	uint8_t newLine = MAX_KEY_SIZE;
	for (int i=0; i< MAX_KEY_SIZE;i++) {
		if (key[i] == '\0') {
			newLine = i;
			break;
		}
	}

	// key input by user is less than 32byte, we need to fill by repetition
	uint16_t passLength = newLine;
	while (newLine < MAX_KEY_SIZE) {
		key[newLine] = key[newLine - passLength];
		newLine++;
	}

	// our secret formula to generate 128bit IV:
	uint8_t iv[] = {	key[2], key[15], key[15], key[8], key[3], key[2], key[3], key[12],
						key[0], key[1],	key[7], key[6], key[7], key[1],key[11], key[2] };	

	struct AES_ctx ctx;
	
	AES_init_ctx_iv(&ctx, key, iv);

	for (int i=1; i<argc; i++) {
		if (i!=mode_index) {
			processDirEntry(argv[i], mode, &ctx);		
		}
	}

	return 0;
}
