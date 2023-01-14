FROM ubuntu:trusty

RUN apt-get update && apt-get install build-essential curl -y

RUN curl -k -L -O https://www.openssl.org/source/old/1.0.1/openssl-1.0.1a.tar.gz \
    && tar -xzvf openssl-1.0.1a.tar.gz \
    && rm openssl-1.0.1a.tar.gz 

RUN curl -k -L -O https://nginx.org/download/nginx-1.10.2.tar.gz  \
    && tar -xzvf nginx-1.10.2.tar.gz \
    && rm nginx-1.10.2.tar.gz \
    && cd nginx-1.10.2\
    && ./configure \
    --with-http_ssl_module \
    --prefix=/usr/local/nginx/ \
    --without-http_gzip_module \
    --with-openssl=/openssl-1.0.1a \
    --without-pcre \
    --with-threads \
    --without-http_rewrite_module \
    && make \
    && make install


RUN cd openssl-1.0.1a \
    && ./config \
    && make \
    && make install_sw

RUN mkdir -p /server/private 

RUN /usr/local/ssl/bin/openssl req -x509 -newkey rsa:4096 -keyout /server/private/privateKey.pem -nodes \
    -days 365 \
    -out /server/private/testCertificate.pem \
    -subj "/C=RO/ST=Romania/L=Bucharest/O=UPB/CN=www.hearthbleed-demo.com"


RUN echo "heart:$(/usr/local/ssl/bin/openssl passwd bleed)" > /server/htpasswd
COPY test.html /server/html/
COPY nginx.conf /usr/local/nginx/conf

EXPOSE 443

CMD echo "Vulnerable Nginx v1.10.2 | OpenSSL v1.0.1a started ..." \
    && /usr/local/nginx/sbin/nginx
