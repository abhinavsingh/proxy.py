FROM cybercoredev/solana:latest AS cli

FROM cybercoredev/evm_loader:latest AS spl

FROM ubuntu:20.04

COPY . /opt
WORKDIR /opt

RUN apt -y update
RUN DEBIAN_FRONTEND=noninteractive apt -y install \
                                          software-properties-common \
                                          openssl \
                                          ca-certificates \
                                          curl \
                                          lsof
RUN add-apt-repository universe
RUN apt -y install python3-pip python3-venv
RUN rm -rf /var/lib/apt/lists/*

COPY --from=cli /opt/solana/bin/solana \
                /opt/solana/bin/solana-faucet \
                /opt/solana/bin/solana-keygen \
                /opt/solana/bin/solana-validator \
                /opt/solana/bin/solana-genesis \
                /cli/bin/

COPY --from=spl /opt/evm_loader.so /spl/bin/
COPY --from=spl /opt/neon-cli /spl/bin/
COPY --from=spl /opt/neon-cli /spl/bin/emulator

RUN python3 -m venv venv
RUN pip3 install --upgrade pip
RUN /bin/bash -c "source venv/bin/activate"
RUN ls .
RUN pip install -r requirements.txt

ENV PATH /venv/bin:/cli/bin/:/spl/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV SOLANA_URL="http://localhost:8899"
ENV EVM_LOADER=HNUNeJDyFWbUuk9o9yrBBpyug9UXqX3Hp9JPZsLvzRno
ENV RUN="echo run-proxy; echo $EVM_LOADER && python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin --num-workers=1 2>&1 | tee /opt/proxy.`date +%Y-%m-%d_%H.%M.%S`.log"
EXPOSE 9090/tcp
#ENTRYPOINT [ "python3" ]
#CMD [ "-m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin --num-workers=1" ]
