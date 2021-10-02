FROM ubuntu:20.04 as pybase

RUN apt-get update -qy && \
    apt-get install -qy python2.7 python2.7-dev python2.7-doc python-pip-whl python3 python3-dev python3-pip virtualenv virtualenvwrapper && \
    apt-get clean -qy

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get install -qy git wget curl vim-tiny nano net-tools libssl-dev libgirepository1.0-dev gobject-introspection cairo-5c libcairo-gobject2 libcairo2-dev pkg-config && \
    apt-get install -qy libpq-dev postgresql-client-common postgresql-common && \
    apt-get clean -qy

WORKDIR /abe

RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && python2.7 get-pip.py && rm get-pip.py

RUN pip2 install wheel
RUN pip2 install cryptography pycryptodome


COPY requirements.txt /abe/
RUN cd /abe && pip2 install -r requirements.txt



FROM pybase as abe

VOLUME /app
WORKDIR /abe

COPY setup.py README.md LICENSE.txt MANIFEST.in /abe/
COPY Abe/ /abe/Abe/
COPY contrib/ /abe/contrib/
COPY tools/ /abe/tools/

#RUN git clone https://github.com/Someguy123/bitcoin-abe.git -b someguy123 && \
#    cd bitcoin-abe && \
RUN cd /abe && python2.7 setup.py install
COPY dkr/ /abe/dkr/
COPY run.sh /abe/
RUN cp /abe/dkr/default.conf /app/abe.conf

VOLUME /blockchain
WORKDIR /app
ARG abe_conf="/app/abe.conf"
ENV abe_conf ${abe_conf}

#RUN echo 'CONFIG_FILE=/abe/dkr/default.conf' >> /abe/.env
RUN echo '[[ -f '${abe_conf}' ]] && : ${CONFIG_FILE='${abe_conf}'} || : ${CONFIG_FILE=/abe/dkr/default.conf}' >> /abe/.env

EXPOSE 2750-2760
EXPOSE 8545-8555

#ENTRYPOINT [ "CONFIG_FILE=/app/abe.conf", "/abe/run.sh", "-c", "${abe_conf}" ]
ENTRYPOINT [ "/abe/run.sh" ]


