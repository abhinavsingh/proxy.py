FROM cybercoredev/solana:latest AS cli

FROM cybercoredev/evm_loader:latest AS spl

FROM python:3.8-alpine as base
# Install openssl to enable TLS interception within container
RUN apk update && apk add openssl
RUN pip install --upgrade pip

COPY --from=cli /opt/solana/bin/solana \
                /opt/solana/bin/solana-faucet \
                /opt/solana/bin/solana-keygen \
                /opt/solana/bin/solana-validator \
                /opt/solana/bin/solana-genesis \
                /cli/bin/

COPY --from=spl /opt/evm_loader.so /spl/bin/
COPY --from=spl /opt/emulator /spl/bin/

RUN python3 -m venv venv
RUN source venv/bin/activate
RUN pip install -r requirements.txt
RUN pip install web3 pysha3
RUN pip install -Iv solana==0.6.5

WORKDIR /proxy

ENV PATH /venv/bin:/cli/bin/:/spl/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EXPOSE 8899/tcp 9090/tcp
ENTRYPOINT [ "python3" ]
CMD [ "-m proxy --hostname 127.0.0.1 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin --num-workers=1" ]
