Heartbleed (CVE-2014-0160)
==========

## Setup

You will require **docker** in order to perform the setup.
The exploit, dynamically generates the random bytes from the Client Hello message,
therefore you will need to link the library when building the executable.
The required package to be installed, in order to link properly:
```
sudo apt-get install libssl-dev
```
The tool was tested on ***Docker for Desktop - Version: 20.10.21*** with ***WSL 2***.

The steps to reproduce the vulnerability are:
1.  Vulnerable server initialization
```
cd server-image/
docker build -t <image_name> .
docker run -d -p <port>:443 --name <name> <image_name>
```
2. Starting the script

```
cd ..
gcc -o heartbleed heartbleed.c -lcrypto
./heartbleed <ip> <port>

```

**You do need to specify the correct port.**

![Heartbleed Leak of 65535 bytes](./resources/heartbleed-dump.png)

## Preview

| Thesis                                                                                                       | Presentation                                                                                                                         |
|--------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| <a href="article/export.pdf"><kbd><img src="article/preview.png" width="400px" alt="Article preview"></kbd></a> | <a href="presentation/export.pdf"><kbd><img src="presentation/preview.png" width="400px" alt="Presentation preview"></kbd></a> |

