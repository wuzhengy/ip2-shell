###  compile
```
1. To run ip2-shell, you need to build ip2 lib, please go to wuzhengy/ip2 to do this as prerequisite
2. make sure following variables existing and correct 
    	 OPENSSL_ROOT	and the /include folder existing 
    	 BOOST_ROOT 
    	 SQLITE_ROOT	and the /include folder existing
3. mkdir build
4. cd build
5. cmake ../
6. make
```

### Run
#### run.sh 
the default mode of ip2 in ip2-shell is server mode, which means it can run as bootstrap. Each node online will seak bootstraps nodes to form up swarm. 

The config file explains: 
 ```
           f49126ba43138eedeb6b51996e8281e1     //device_id not really important, as long as it unique, it is a field ref hardward
			null    //seed, if set to null, a random seed will generated 
            tau://83024767468B8BF8DB868F336596C63561265D553833E5C0BF3E4767659B826B@13.229.53.249:6882 // boot strap node to start with
            ./pid.txt
            ./error.txt
            ./debug.txt
            6882     //ip2 swarm listenning port
            8080     //rpc port for rpc call and command
            /data/TAU_SHELL/TAU_TEST //ip-shell data folder 
            .libTAU_test    //libip2 own data folder
```
#### rpc cmd使用
./rpc.sh
```
#curl -H "Content-Type: application/json"   --user tau-shell:tester    -X POST  --data '{"method":"get-block-by-hash", "arguments":{"chain_id": "15701c56ad4a8dbd54657374436861696e", "block_hash": "15701c56ad4a8dbd54657374436861696e"}}' http://localhost:8080/rpc ;


--user tau-shell:tester  //rpc用户密码，可以在main函数中修改

 "arguments":{"chain_id": "15701c56ad4a8dbd54657374436861696e", "block_hash": "15701c56ad4a8dbd54657374436861696e"}}' //参数传递
 
 http://localhost:8080/rpc ;   //8080是config中的rpc端口
```
