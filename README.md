## About
```pst``` is a simple HTTP **P**roxy **S**tress **T**est utility.

## Installing
This project is written in the [Go](http://golang.org/) programming language and to build it you need to install Go compiler and set some enviroment variables. [Here is an instructions on how to do it](http://golang.org/doc/install). After you've done all requered steps run the following command in your shell:
```
$ go get github.com/thekvs/pst
```
and this will build the binary in ```$GOPATH/bin```.

## Usage examples
```
$ ./pst -c 100 -d 2m -u /tmp/urls.txt -p http://john:mycoolpass@proxy.example.com:3128
```
Run stress test for (approximately) 2 minutes using 100 open connections to the proxy on address ```proxy.example.com:3128```. continuously submit urls from file ```/tmp/urls.txt```.


```
$ ./pst -c 100 -R 1000 -u /tmp/urls.txt -p http://john:mycoolpass@proxy.example.com:3128
```
Submit urls from file ```/tmp/urls.txt``` 1000 times making 100 simultaneous connections to the proxy. In the ideal situation each connection should submit 10 urls.


```
$ ./pst -c 100 -r 100 -u /tmp/urls.txt -p http://john:mycoolpass@proxy.example.com:3128
```
Submit urls from file ```/tmp/urls.txt``` 100 times in *each* connection making 100 simultaneous connections to the proxy. I.e. in total 10000 urls will be requested through proxy.

For more options see output ```./pst -h```.

## Licensing
All source code included in this distribution is covered by the MIT License found in the LICENSE file.
