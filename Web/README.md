# WEB

## ezblog

two tricks, one is db_trick, and the other is ???

Attachment:

Other regions:
https://drive.google.com/file/d/1f9Rl6RnCHFSZvStqdDu5t3RxXUqcvd7b/view?usp=sharing

## ezblog2

ezblog, now with more secure and less unintended

```
diff --color -r env/docker/docker-compose.yml env2/docker/docker-compose.yml 
5c5 
<     image: wmctf2023_ezblog
--- 
>     image: wmctf2023_ezblog2
diff --color -r env/src/src/app.ts env2/src/src/app.ts
248a249,251
>     try{
>         child_process.execSync("chmod -R 444 /home/ezblog/views/*") 
>     } catch (e) { } 
```