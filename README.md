
## Theta


A rainbow table based password cracker

that can crack a very vast number of hashing algorithms as follows.

```text
        md2           
        md4             md5             sha0            sha1          
        sha224          sha256          sha384          sha512        
        ripemd          ripemd128       ripemd160       tiger         
        tiger2          panama          haval256_3      haval256_4    
        haval256_5      whirlpool       radiogatun32    radiogatun64  
        shabal224       shabal256       shabal384       shabal512     
        echo224         echo256         echo384         echo512       
        simd224         simd256         simd384         simd512       
        luffa224        luffa256        luffa384        luffa512      
        blake224        blake256        blake384        blake512      
        skein224        skein256        skein384        skein512      
        jh224           jh256           jh384           jh512         
        fugue224        fugue256        fugue384        fugue512      
        bmw224          bmw256          bmw384          bmw512        
        cubehash224     cubehash256     cubehash384     cubehash512   
        keccak224       keccak256       keccak384       keccak512     
        groestl224      groestl256      groestl384      groestl512    
        hamsi224        hamsi256        hamsi384        hamsi512      
        shavite224      shavite256      shavite384      shavite512     
```


## Installation

For installing run

```
git clone https://github.com/curious-builder76/theta.git theta

cd theta 

chmod +x build.sh

./build.sh

``` 

which will create a binary `theta` on the working directory `theta`


## Usage


```bash

# for creating databases run


./theta create "<wordlist>" "<algorithm>" "<outfile>"   "[bucket-size]"

# for example assuming there exists a hypothetical wordlist wordlist.txt and we
# want to create a database (or rainbow table) named wordlist-md5.db 
# that consists of passwords from wordlist.txt 

./theta create wordlist.txt md5 wordlist-md5.db # which outputs wordlist-md5.db 
                                                # on the present working directory.

./theta create wordlist.txt sha1 wordlist-sha1.db # or say we wish to create wordlist-sha1.db
                                                  # on the present working directory which 
                                                  # now contains the same thing but will be 
                                                  # used to crack sha1 hashes :P





# for cracking passwords run 

./theta crack "<table-file>" "<algorithm>" "<hash-candidate-or-so-called-target>"

# for example we want to crack a md5 hash  of 
# "hello1234" ( md5-hash: 9a1996efc97181f0aee18321aa3b3b12)
# from our previously created database "wordlist-md5.db" 
# we run 

./theta crack wordlist-md5.db md5 9a1996efc97181f0aee18321aa3b3b12

```
which shall ouput

```text
Cracking...
database: wordlist-md5.db algorithm: md5 target: 9a1996efc97181f0aee18321aa3b3b12
Target: 9a1996efc97181f0aee18321aa3b3b12
Recovered: hello1234
```

## Demonstration of the bucket-size option
```bash
# Assume that we have a wordlist, say  the infamous rockyou.txt
# upon running the command 

./theta create rockyou.txt md5 rockyou-md5.db

# which will take 19 minutes to create itself.
# now running

./theta create rockyou.txt md5 rockyou-md5.db 65536

# will take just 30 seconds.
```

## Features

- Super fast hash cracking and table generation.
- Can create databases of extremely large wordlists.
- Follows principle of `cry once and then cry never`
- Can crack wide variety of hashes

## Cons

- Only made for Linux 64 bit machines.
- Rejects password length greater than or equal to 64.

## License

- Licensed under GPL v3

## Warning

- The program trusts the user blindly and will run on malicious data file without checking. It's a trade off made in attempt to as fastest as possible 
