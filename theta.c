
/*
    Password cracker based upon lookup tables (a.k.a Rainbow tables) on disk.
    Copyright (C) Rahul (GitHub: curious-builder76)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<time.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<fcntl.h>
#include<unistd.h>
#include<inttypes.h>

#include "sph_blake.h"
#include "sph_bmw.h"
#include "sph_cubehash.h"
#include "sph_echo.h"
#include "sph_fugue.h"
#include "sph_groestl.h"
#include "sph_hamsi.h"
#include "sph_haval.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_luffa.h"
#include "sph_md2.h"
#include "sph_md4.h"
#include "sph_md5.h"
#include "sph_panama.h"
#include "sph_radiogatun.h"
#include "sph_ripemd.h"
#include "sph_sha0.h"
#include "sph_sha1.h"
#include "sph_sha2.h"
#include "sph_shabal.h"
#include "sph_shavite.h"
#include "sph_simd.h"
#include "sph_skein.h"
#include "sph_tiger.h"
#include "sph_whirlpool.h"


#define MAX_LEN  64

#define INT_fmt PRIu32


typedef struct{
	size_t hash;
	char buff[MAX_LEN];
}record_t;




typedef struct{
	size_t used;
}bucket_t;


typedef struct{
	size_t table_size;
	size_t malloced;
	size_t bucket_size;
}table_t;



size_t hash_key(char* key){
	size_t hash=5831;
	while(*key){
		size_t c=*key++;
		hash= (hash<<5)+ hash +c;
	}
	return hash;
}

table_t* table_new(uint16_t bucket_size){
	size_t table_size=1024;
	size_t mem_required=sizeof(table_t) + (sizeof(bucket_t) + sizeof(record_t)*bucket_size)*table_size;
	table_t* table=malloc(mem_required);
	if(!table)
		return table;
	memset(table,0,mem_required);
	table->table_size=table_size;
	table->bucket_size=bucket_size;
	table->malloced=mem_required;
	return table;
}



#define POSITION(bucket_index,bucket_size) (sizeof(table_t) + (sizeof(bucket_t)+ sizeof(record_t)*bucket_size)*bucket_index)

bucket_t*  get_bucket(table_t* table,size_t index){
	return (bucket_t*)((char*)table + POSITION(index,table->bucket_size));
}


#define GROW_AT 0.6

int shall_grow(table_t* table){
	for(size_t idx=0;idx<table->table_size;idx++){
		bucket_t* bucket=get_bucket(table,idx);
		double lf= (double) bucket->used / (double) table->bucket_size;
		if(lf>=GROW_AT){
			return 1;
		}
	}
	return 0;
}


int table_put0(table_t* table,size_t hash,char* buff){
	size_t index= hash % table->table_size;
	bucket_t* bucket= get_bucket(table,index);
	if(bucket->used>=table->bucket_size){
		fprintf(stderr,"Bucket id: %lu\n", index);
		return 1;
	}
	record_t* record=(record_t*)((char*) bucket+sizeof(bucket))+ (bucket->used++);
	record->hash=hash;
	strcpy(record->buff,buff);
	return 0;
}

table_t* table_grow(table_t* table){
	printf("Table is growing...\n");
	fflush(stdout);
	size_t growth_by=2;
	size_t new_size= table->malloced*growth_by - sizeof(table_t)*(growth_by-1);
	table_t* new_table=malloc(new_size);
	if(!new_table){
		return NULL;
	}
	memset(new_table,0,new_size);
	new_table->table_size=table->table_size*2;
	new_table->bucket_size=table->bucket_size;
	new_table->malloced=new_size;
	for(size_t idx=0;idx<table->table_size;idx++){
		bucket_t* bucket=get_bucket(table,idx);
		record_t* records =(record_t*) (bucket+1);
		for(size_t n=0;n<bucket->used;n++){
			record_t* record=records+n;
			if(table_put0(new_table,record->hash,record->buff)){
				fprintf(stderr,"Error: bucket overflow\n");
				free(new_table);
				return NULL;
			}
		}
	}
	free(table);
	table=NULL;
	return new_table;
}


#define HASH_SIZE(name) ((SPH_SIZE_ ## name) >>3)

#define CREATE_CRACKER(name)\
	static char* hash_ ## name ## _hex(char* key,char* out){\
		char* hexmap="0123456789abcdef";\
		sph_ ## name ## _context ctx;\
		unsigned char hash[HASH_SIZE(name)];\
		sph_ ## name ## _init(&ctx);\
		sph_ ## name (&ctx,key,strlen(key));\
		sph_ ## name ## _close(&ctx,hash);\
		for(int i=0;i<HASH_SIZE(name);i++){\
			out[i*2]=hexmap[hash[i]>>4];\
			out[i*2+1]=hexmap[hash[i]&0x0f];\
		}\
		out[2*HASH_SIZE(name)]='\0';\
		return out;\
	}\
	void table_crack_ ##name (table_t* table,char* target){\
		char stored[1+2*HASH_SIZE(name)];\
		size_t hash=hash_key(target);\
		size_t index=hash % table->table_size;\
		bucket_t* bucket=get_bucket(table,index);\
		record_t* records=(record_t*)((char*)bucket+sizeof(bucket_t));\
		char found=0;\
		for(size_t idx=0;idx<bucket->used;idx++){\
			record_t* record=records+idx;\
			if(record->hash!=hash){\
				continue;\
			}\
			char* digest=hash_ ## name ## _hex(record->buff,stored);\
			if(strcmp(digest,target)==0){\
				found=1;\
				fprintf(stderr,"Target: %s\nRecovered: %s\n",target,record->buff);\
				break;\
			}\
		}\
		if(!found){\
			fprintf(stderr,"Failed to recover: %s\n",target);\
		}\
	}\
	table_t* table_put_## name(table_t* table,char* plaintext){\
		if(shall_grow(table)){\
			table_t* tmp=table_grow(table);\
			if(!tmp){\
				return NULL;\
			}\
			table=tmp;\
		}\
		char stored[1+2*HASH_SIZE(name)];\
		char* digest= hash_ ## name ## _hex(plaintext,stored);\
		size_t table_hash = hash_key(digest);\
		size_t index= table_hash % table->table_size;\
		bucket_t* bucket= get_bucket(table,index);\
		record_t* record= (record_t*)((char*)bucket+ sizeof(bucket_t))+(bucket->used++);\
		record->hash=table_hash;\
		strcpy(record->buff,plaintext);\
		return table;\
	}


void table_dump(table_t* table,char* filename){
	FILE* outfile=fopen(filename,"wb");
	if(!outfile){
		perror("fopen()");
		return;
	}
	fwrite(table,table->malloced,1,outfile);
	perror("fwrite");
	fclose(outfile);
}

CREATE_CRACKER(md2)
CREATE_CRACKER(md4)
CREATE_CRACKER(md5)
CREATE_CRACKER(sha0)
CREATE_CRACKER(sha1)
CREATE_CRACKER(sha224)
CREATE_CRACKER(sha256)
CREATE_CRACKER(sha384)
CREATE_CRACKER(sha512)
CREATE_CRACKER(ripemd)
CREATE_CRACKER(ripemd128)
CREATE_CRACKER(ripemd160)
CREATE_CRACKER(tiger)
CREATE_CRACKER(tiger2)
CREATE_CRACKER(panama)
CREATE_CRACKER(haval256_3)
CREATE_CRACKER(haval256_4)
CREATE_CRACKER(haval256_5)
CREATE_CRACKER(whirlpool)
CREATE_CRACKER(radiogatun32)
CREATE_CRACKER(radiogatun64)
CREATE_CRACKER(shabal224)
CREATE_CRACKER(shabal256)
CREATE_CRACKER(shabal384)
CREATE_CRACKER(shabal512)
CREATE_CRACKER(echo224)
CREATE_CRACKER(echo256)
CREATE_CRACKER(echo384)
CREATE_CRACKER(echo512)
CREATE_CRACKER(simd224)
CREATE_CRACKER(simd256)
CREATE_CRACKER(simd384)
CREATE_CRACKER(simd512)
CREATE_CRACKER(luffa224)
CREATE_CRACKER(luffa256)
CREATE_CRACKER(luffa384)
CREATE_CRACKER(luffa512)
CREATE_CRACKER(blake224)
CREATE_CRACKER(blake256)
CREATE_CRACKER(blake384)
CREATE_CRACKER(blake512)
CREATE_CRACKER(skein224)
CREATE_CRACKER(skein256)
CREATE_CRACKER(skein384)
CREATE_CRACKER(skein512)
CREATE_CRACKER(jh224)
CREATE_CRACKER(jh256)
CREATE_CRACKER(jh384)
CREATE_CRACKER(jh512)
CREATE_CRACKER(fugue224)
CREATE_CRACKER(fugue256)
CREATE_CRACKER(fugue384)
CREATE_CRACKER(fugue512)
CREATE_CRACKER(bmw224)
CREATE_CRACKER(bmw256)
CREATE_CRACKER(bmw384)
CREATE_CRACKER(bmw512)
CREATE_CRACKER(cubehash224)
CREATE_CRACKER(cubehash256)
CREATE_CRACKER(cubehash384)
CREATE_CRACKER(cubehash512)
CREATE_CRACKER(keccak224)
CREATE_CRACKER(keccak256)
CREATE_CRACKER(keccak384)
CREATE_CRACKER(keccak512)
CREATE_CRACKER(groestl224)
CREATE_CRACKER(groestl256)
CREATE_CRACKER(groestl384)
CREATE_CRACKER(groestl512)
CREATE_CRACKER(hamsi224)
CREATE_CRACKER(hamsi256)
CREATE_CRACKER(hamsi384)
CREATE_CRACKER(hamsi512)
CREATE_CRACKER(shavite224)
CREATE_CRACKER(shavite256)
CREATE_CRACKER(shavite384)
CREATE_CRACKER(shavite512)

struct{
	char* name;
	void (*cracker)(table_t* ,char* );
	table_t* (*updater)(table_t* ,char* );
}targets[]={
	{"md2", table_crack_md2, table_put_md2},
	{"md4", table_crack_md4, table_put_md4},
	{"md5", table_crack_md5, table_put_md5},
	{"sha0", table_crack_sha0, table_put_sha0},
	{"sha1", table_crack_sha1, table_put_sha1},
	{"sha224", table_crack_sha224, table_put_sha224},
	{"sha256", table_crack_sha256, table_put_sha256},
	{"sha384", table_crack_sha384, table_put_sha384},
	{"sha512", table_crack_sha512, table_put_sha512},
	{"ripemd", table_crack_ripemd, table_put_ripemd},
	{"ripemd128", table_crack_ripemd128, table_put_ripemd128},
	{"ripemd160", table_crack_ripemd160, table_put_ripemd160},
	{"tiger", table_crack_tiger, table_put_tiger},
	{"tiger2", table_crack_tiger2, table_put_tiger2},
	{"panama", table_crack_panama, table_put_panama},
	{"haval256_3", table_crack_haval256_3, table_put_haval256_3},
	{"haval256_4", table_crack_haval256_4, table_put_haval256_4},
	{"haval256_5", table_crack_haval256_5, table_put_haval256_5},
	{"whirlpool", table_crack_whirlpool, table_put_whirlpool},
	{"radiogatun32", table_crack_radiogatun32, table_put_radiogatun32},
	{"radiogatun64", table_crack_radiogatun64, table_put_radiogatun64},
	{"shabal224", table_crack_shabal224, table_put_shabal224},
	{"shabal256", table_crack_shabal256, table_put_shabal256},
	{"shabal384", table_crack_shabal384, table_put_shabal384},
	{"shabal512", table_crack_shabal512, table_put_shabal512},
	{"echo224", table_crack_echo224, table_put_echo224},
	{"echo256", table_crack_echo256, table_put_echo256},
	{"echo384", table_crack_echo384, table_put_echo384},
	{"echo512", table_crack_echo512, table_put_echo512},
	{"simd224", table_crack_simd224, table_put_simd224},
	{"simd256", table_crack_simd256, table_put_simd256},
	{"simd384", table_crack_simd384, table_put_simd384},
	{"simd512", table_crack_simd512, table_put_simd512},
	{"luffa224", table_crack_luffa224, table_put_luffa224},
	{"luffa256", table_crack_luffa256, table_put_luffa256},
	{"luffa384", table_crack_luffa384, table_put_luffa384},
	{"luffa512", table_crack_luffa512, table_put_luffa512},
	{"blake224", table_crack_blake224, table_put_blake224},
	{"blake256", table_crack_blake256, table_put_blake256},
	{"blake384", table_crack_blake384, table_put_blake384},
	{"blake512", table_crack_blake512, table_put_blake512},
	{"skein224", table_crack_skein224, table_put_skein224},
	{"skein256", table_crack_skein256, table_put_skein256},
	{"skein384", table_crack_skein384, table_put_skein384},
	{"skein512", table_crack_skein512, table_put_skein512},
	{"jh224", table_crack_jh224, table_put_jh224},
	{"jh256", table_crack_jh256, table_put_jh256},
	{"jh384", table_crack_jh384, table_put_jh384},
	{"jh512", table_crack_jh512, table_put_jh512},
	{"fugue224", table_crack_fugue224, table_put_fugue224},
	{"fugue256", table_crack_fugue256, table_put_fugue256},
	{"fugue384", table_crack_fugue384, table_put_fugue384},
	{"fugue512", table_crack_fugue512, table_put_fugue512},
	{"bmw224", table_crack_bmw224, table_put_bmw224},
	{"bmw256", table_crack_bmw256, table_put_bmw256},
	{"bmw384", table_crack_bmw384, table_put_bmw384},
	{"bmw512", table_crack_bmw512, table_put_bmw512},
	{"cubehash224", table_crack_cubehash224, table_put_cubehash224},
	{"cubehash256", table_crack_cubehash256, table_put_cubehash256},
	{"cubehash384", table_crack_cubehash384, table_put_cubehash384},
	{"cubehash512", table_crack_cubehash512, table_put_cubehash512},
	{"keccak224", table_crack_keccak224, table_put_keccak224},
	{"keccak256", table_crack_keccak256, table_put_keccak256},
	{"keccak384", table_crack_keccak384, table_put_keccak384},
	{"keccak512", table_crack_keccak512, table_put_keccak512},
	{"groestl224", table_crack_groestl224, table_put_groestl224},
	{"groestl256", table_crack_groestl256, table_put_groestl256},
	{"groestl384", table_crack_groestl384, table_put_groestl384},
	{"groestl512", table_crack_groestl512, table_put_groestl512},
	{"hamsi224", table_crack_hamsi224, table_put_hamsi224},
	{"hamsi256", table_crack_hamsi256, table_put_hamsi256},
	{"hamsi384", table_crack_hamsi384, table_put_hamsi384},
	{"hamsi512", table_crack_hamsi512, table_put_hamsi512},
	{"shavite224", table_crack_shavite224, table_put_shavite224},
	{"shavite256", table_crack_shavite256, table_put_shavite256},
	{"shavite384", table_crack_shavite384, table_put_shavite384},
	{"shavite512", table_crack_shavite512, table_put_shavite512},
	{NULL,NULL,NULL},
};

void print_available(){
	printf("\nAvailable algorithms: \n");
	size_t idx=0;
	while (1){
		if(targets[idx].name==NULL) {
			return;
		}
		printf("\t%-14s",targets[idx].name);
		if(!(idx&7)){
			puts("");
		}
		idx++;
	}
}

void crack_hash(char* filename,char* algorithm,char* target){
	void (*crack)(table_t*, char* );
	size_t idx=0;
	while (1){
		if(targets[idx].name==NULL) {
			printf("Unkown algorithm: %s",algorithm);
			print_available();
			return;
		}
		if(!strcmp(targets[idx].name,algorithm)){
			crack=targets[idx].cracker;
			break;
		}
		idx++;
	}
	int fd=open(filename,O_RDONLY);
	if(fd==-1){
		perror("open()");
		return;
	}
	struct stat st;
	if(fstat(fd,&st)==-1){
		perror("fstat()");
		goto failed;
	}
	size_t size=st.st_size;
	void* mem=mmap(NULL,size,PROT_READ, MAP_PRIVATE,fd,0);
	if(mem==MAP_FAILED){
		perror("mmap");
		goto failed;
	}
	table_t* table=mem;
	crack(table,target);
	munmap(mem,size);
failed:
	close(fd);
}

void create_table(char* infile,char* outfile,char* algorithm,size_t bucket_size){
	table_t* (*callback)(table_t*, char* );
	size_t idx=0;
	while (1){
		if(targets[idx].name==NULL) {
			printf("Unkown algorithm: %s",algorithm);
			print_available();
			return;
		}
		if(!strcmp(targets[idx].name,algorithm)){
			callback=targets[idx].updater;
			break;
		}
		idx++;

	}
	int fd=-1;
	table_t* table=NULL;
	char* mmaped_buffer=NULL;
	size_t size=0;
	size_t buffer_size=1024;
	size_t offset=0;
	size_t lineno=0;
	char* buffer=NULL;
	char* tmp_buffer=NULL;
	table_t* tmp_table=NULL;

	table=table_new(bucket_size);
	if(!table){
		perror("malloc");
		goto failed;
	}
	fd=open(infile,O_RDONLY);
	if(fd==-1){
		perror("open()");
		goto failed;
	}

	struct stat st;

	if(fstat(fd,&st)==-1){
		perror("fstat()");
		goto failed;
	}

	size=st.st_size;

	mmaped_buffer=mmap(NULL,size,PROT_READ,MAP_PRIVATE,fd,0);
	if(mmaped_buffer==MAP_FAILED){
		perror("mmap()");
		goto failed;
	}

	buffer=malloc(buffer_size);
	if(!buffer){
		perror("malloc()");

		goto failed;
	}

	while(offset<size){
		lineno++;
		char* start=mmaped_buffer+offset;
		char* nl=memchr(start,'\n',size-offset);
		if(!nl){
			break;
		}
		size_t len=nl-start;
		while(len+1>=buffer_size){
			buffer_size*=2;
			tmp_buffer=realloc(buffer,buffer_size);
			if(!tmp_buffer){
				goto failed;
			}
			buffer=tmp_buffer;

		}
		memcpy(buffer,start,len);
		buffer[len]=0;
		offset+=(len+1);
		if(len>=64){
			fprintf(stderr,"Rejected line: %lu\n",lineno);
			fflush(stderr);
			continue;
		}
		printf("lineno: %lu\r",lineno);
		fflush(stdout);
		tmp_table=callback(table,buffer);
		if(!tmp_table){
			fprintf(stderr,"Due to some reasons. the creation of table failed\n"
					"Aborting...\n");
			goto failed;
		}

		table=tmp_table;
	}
	table_dump(table,outfile);


failed:
	if(mmaped_buffer!=NULL) munmap(mmaped_buffer,size);
	if(fd!=-1) close(fd);
	if(table!=NULL) free(table);
	if(buffer!=NULL) free(buffer);
}


#define CRACK (1<<2)
#define CREATE (1<<3)
int main(int argc, char* argv[]){
	if(argc==1){
help:
		fprintf(stderr,
				"%s crack <table file> <algorithm> <target hash> # Crack an hash through given table\n"
				"%s create <wordlist> <algorithm> <outfile>  [bucket_size] # Create a fresh "
				"wordlist file (overwrites old ones if they exist.)\n"
				"# Arguments inside \"<\"  \">\" are compulsary.\n"
				"# Arguments inside \"[\"  \"]\" are are optional.\n",
				argv[0],
				argv[0]
		       );
		return 1;
	}
	uint8_t flags= 0;
	if(argc>=2){
		if(!strcmp(argv[1],"create")){
			flags|=CREATE;
		}
		if(!strcmp(argv[1],"crack")){
			flags|=CRACK;
		}
		if(flags & (CREATE | CRACK)){

		argc--;
		argv++;
		argc--;
		argv++;
		}

	}
	// Pop switch and argv[0] out.
	if( flags & CRACK){
		if (argc!=3){
			printf("Error: expected %d arguments got %d ",3,argc);
			return 1;
		}
		puts("Cracking...");

		printf("database: %s algorithm: %s target: %s\n",argv[0],argv[1],argv[2]);
		crack_hash(argv[0],argv[1],argv[2]);
		return 0;

	} else	if(flags & CREATE){
		uint16_t bucket_size=64;
		char* wordlist=NULL;
		char* outfile=NULL;
		char* algorithm=NULL;
		if(argc>4 || argc<3){
			printf("Error: expected %d or %d  arguments got %d\n",4 , 3 ,argc);
			return 1;
		}
		size_t tmp;
		switch (argc){
			case 4:
				tmp=atoi(argv[3]);
				tmp =  tmp<=0 ? 0 : tmp;
				bucket_size= (uint16_t)(tmp ? tmp : bucket_size);
				/* fall through */
			case 3:
				outfile=argv[2];
				algorithm=argv[1];
				wordlist=argv[0];
				break;
			default:
				return 1;
		}
		puts("Creating...");
		printf("wordlist: %s outfile: %s algorithm: %s bucket_size: %u\n" ,wordlist,outfile,algorithm,bucket_size);
		create_table(wordlist,outfile,algorithm,bucket_size);
	}
	else{
		printf("Unkown options.\n");
		goto help;
	}
	return 0;
}
