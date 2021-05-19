ARG SOLANA_REVISION=9e68ded325b8ceb25d346cd6e2656f790ba89033
ARG EVM_LOADER_REVISION=7d873f6d9b00feba7f80dcad5a4e74023ab3b80c

FROM cybercoredev/solana:9e68ded325b8ceb25d346cd6e2656f790ba89033 AS cli

FROM cybercoredev/evm_loader:7d873f6d9b00feba7f80dcad5a4e74023ab3b80c AS spl

FROM ubuntu:20.04

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt -y install \
            software-properties-common openssl curl \
            ca-certificates python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt /opt
WORKDIR /opt

RUN python3 -m venv venv && \
    pip3 install --upgrade pip && \
    /bin/bash -c "source venv/bin/activate" && \
    pip install -r requirements.txt

COPY --from=cli /opt/solana/bin/solana \
                /opt/solana/bin/solana-faucet \
                /opt/solana/bin/solana-keygen \
                /opt/solana/bin/solana-validator \
                /opt/solana/bin/solana-genesis \
                /cli/bin/

COPY --from=spl /opt/solana/bin/solana /cli/bin/
COPY --from=spl /opt/evm_loader.so \
                /opt/neon-cli /spl/bin/
COPY --from=spl /opt/neon-cli /spl/bin/emulator

COPY . /opt

ENV PATH /venv/bin:/cli/bin/:/spl/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV SOLANA_URL="http://localhost:8899"

EXPOSE 9090/tcp
ENTRYPOINT [ "./proxy/run-proxy.sh" ]
