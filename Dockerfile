ARG SOLANA_REVISION=v1.9.12-testnet-with_trx_cap
ARG NEON_EVM_COMMIT=latest

FROM neonlabsorg/solana:${SOLANA_REVISION} AS cli

FROM neonlabsorg/evm_loader:${NEON_EVM_COMMIT} AS spl

FROM ubuntu:20.04

COPY ./requirements.txt /opt

WORKDIR /opt

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y git software-properties-common openssl curl parallel \
                                                  ca-certificates python3-pip python3-venv postgresql-client && \
    python3 -m venv venv && \
    pip3 install --upgrade pip && \
    /bin/bash -c "source venv/bin/activate" && \
    pip install -r requirements.txt && \
    pip3 install py-solc-x && \
    python3 -c "import solcx; solcx.install_solc(version='0.7.6')" && \
    apt remove -y git && \
    rm -rf /var/lib/apt/lists/*

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
COPY --from=spl /opt/neon-cli /spl/bin/
COPY --from=spl /opt/solana_utils.py \
                /opt/eth_tx_utils.py \
                /spl/bin/
COPY --from=spl /opt/neon-cli /spl/bin/emulator

COPY proxy/operator-keypairs/id.json /root/.config/solana/

COPY . /opt
ARG PROXY_REVISION
ARG LOG_CFG=log_cfg.json
RUN (cp -f /opt/${LOG_CFG} /opt/log_cfg.json || true)
RUN sed -i 's/NEON_PROXY_REVISION_TO_BE_REPLACED/'"$PROXY_REVISION"'/g' /opt/proxy/plugin/solana_rest_api.py

COPY ./proxy/solana-py.patch /opt
RUN cd /usr/local/lib/python3.8/dist-packages/ && patch -p0 </opt/solana-py.patch

ENV PATH /venv/bin:/cli/bin/:/spl/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV CONFIG="devnet"

EXPOSE 9090/tcp
ENTRYPOINT [ "./proxy/run-proxy.sh" ]
