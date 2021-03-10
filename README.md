# fuzzparam

## What is?

A fast go based param miner to fuzz possible parameters a URL can have.

TL;DR
> Give it list of URL's and it will find the parameters that URL will have


## Download

Download and Build it using following command:
```
$ git clone https://github.com/0xsapra/fuzzparam
$ cd fuzzparam
$ go build fuzzparam.go  
```


## Flags supported

| Flag      | Description | Example |
| ----------- | ----------- | ----------- |
| -X      | HTTP Method       | -X POST |
| -x   | Proxy Url        | -x http://127.0.0.1:8080 |
| -c   | Concurrency/threads(Default 25)        | -c 100 |
| -H   | Headers        | -H "Cookie: test:1" -H "X-Forwarded-For: x.com" |
| -w   | Path to wordlist        | -w ./parameters.txt  |


## Usage

```bash
$ ./fuzzparam -X GET -w ./parameters.txt -H "Cookie: asdf" https://site.com 
```

OR
```bash
$ echo "https://site.com\nhttps://site2.com\nhttps://site.com/asdf.php\n" > domains.txt

$ cat domains.txt | ./fuzzparam -w ./parameters.txt -H "Cookie: asdg"
```

OR, 
use it will other tools. Like projectdiscovery's `httpx`. [https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)
and, tomnonnom's `waybackurls` [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls)

```bash
$ cat domains.txt | waybackurls | httpx | fuzzparam -w ./parameters.txt > finalUrlsWithParams.txt
```
