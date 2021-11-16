ARG SOLANA_REVISION=v1.7.9-resources
ARG EVM_LOADER_REVISION=stable

FROM neonlabsorg/solana:${SOLANA_REVISION} AS cli

FROM neonlabsorg/evm_loader:${EVM_LOADER_REVISION} AS spl

FROM ubuntu:20.04

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt -y install \
            software-properties-common openssl curl \
            ca-certificates python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt /opt
COPY ./proxy/solana-py.patch /opt
WORKDIR /opt

RUN python3 -m venv venv && \
    pip3 install --upgrade pip && \
    /bin/bash -c "source venv/bin/activate" && \
    pip install -r requirements.txt && \
    pip install py-solc-x

COPY --from=cli /opt/solana/bin/solana \
                /opt/solana/bin/solana-faucet \
                /opt/solana/bin/solana-keygen \
                /opt/solana/bin/solana-validator \
                /opt/solana/bin/solana-genesis \
                /cli/bin/

COPY --from=spl /opt/solana/bin/solana /cli/bin/
COPY --from=spl /opt/spl-token \
                /opt/create-test-accounts.sh \
                /opt/evm_loader-keypair.json /spl/bin/
COPY --from=spl /opt/neon-cli /opt/faucet /spl/bin/
COPY --from=spl /opt/solana_utils.py \
                /opt/eth_tx_utils.py \
                /spl/bin/
COPY --from=spl /opt/neon-cli /spl/bin/emulator

COPY . /opt
COPY proxy/operator-keypair.json /root/.config/solana/id.json
RUN cd /usr/local/lib/python3.8/dist-packages/ && patch -p0 </opt/solana-py.patch

ENV PATH /venv/bin:/cli/bin/:/spl/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV CONFIG="devnet"

EXPOSE 9090/tcp
ENTRYPOINT [ "./proxy/run-proxy.sh" ]
