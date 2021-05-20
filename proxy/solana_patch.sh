#!/bin/sh
patch_file=/usr/local/lib/python3.8/dist-packages/solana/rpc/api.py
sed -i 's/tx_sig: str, encoding: str = \"json\")/tx_sig: str, encoding: str = \"json\", commitment = \"confirmed\")/g' $patch_file
sed -i 's/tx_sig, encoding/tx_sig, \{self._comm_key: commitment, self._encoding_key: encoding\}/g' $patch_file
echo $patch_file   ... PATCHED