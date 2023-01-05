FROM ubuntu

# build-essential is a meta package, meaning it esentially doesn't install anything
# instead, it contains links to several dependencies required for using the OpenSSL library

# gcc - GNU C compiler
# g++ - GNU C++ compiler
# libc6-dev - GNU C library
# make - compilation tool

# git is required for cloning the repository containing the vulnerable version of OpenSSL library
# OpenSSL 1.0.1 through 1.0.1f as specified in CVE-2014-0160 (https://nvd.nist.gov/vuln/detail/cve-2014-0160)

RUN apt-get update && \
    apt install -y build-essential git

# OpenSSL installation is done as specified in the quick start section from the INSTALL file 
# OpenSSL_1_0_1a - https://github.com/openssl/openssl/blob/OpenSSL_1_0_1a/INSTALL


RUN git clone https://github.com/openssl/openssl.git && \
    cd openssl && \
    git checkout OpenSSL_1_0_1a && \
    ./config && \
    make && \
    make install_sw


# Identified Problems:
# make test fails due to the fact that 1.0.1 is no longer supported

# Steps for generating demo service self-signed certificate and private key

# openssl req - PKCS#10 certificate request and certificate generating utility
# FLAGS:
# -x509 - Output a x509 structure instead of a cert request
# -newkey <type>:<bits> - Generates a new private key with the specified format
# -keyout <filepath> - Output the generated private key to the specified file
# -nodes - Don't encrypt the output key
# -days <+int> - Number of days certificate is valid for
# -out <filepath> -  Output file
# -subj <val> - Set or modify request subject 
# - Distinguished Names description (https://www.ibm.com/docs/en/ibm-mq/7.5?topic=certificates-distinguished-names)
# - https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4
RUN openssl/apps/openssl req -x509 -newkey rsa:4096 -keyout privateKey.pem -nodes \
    -days 365 \
    -out testCertificate.pem \
    -subj "/C=RO/ST=Romania/L=Bucharest/O=UPB/CN=www.hearthbleed-demo.com"


# openssl s_server - generic SSL/TLS server which listens for connections on a given port using SSL/TLS
# FLAGS:
# -key <filepath> - private key to use for the communication if not specified in the given certificate
# -cert <filepath> - certificate used for the communication
# -accept - TCP/IP optional host and port to listen on for connections (default is *:4433)
# -www - sends a status message back to the client when it connects. (response to a GET /)
#        This includes lots of information about the ciphers used and various session parameters.
#        The output is in HTML format so this option will normally be used with a web browser.
ENTRYPOINT [ "openssl/apps/openssl", "s_server", "-key" ,"privateKey.pem", \
             "-cert", "testCertificate.pem", "-accept", "8443", "-www" ]