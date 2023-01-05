# HeartBleed Exploit Demo




```
$ git clone https://github.com/undacmic/HeartBleed-Demo.git
$ cd HearthBleed-Demo
$ docker build -t heartbleed-demo .
$ docker run -it --rm -p 8443:8443 --name heartbleed-demo heartbleed-demo
```