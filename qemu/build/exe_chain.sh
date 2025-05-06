killall swtpm 2>/dev/null

rm -rf /tmp/tpm
mkdir -p /tmp/tpm
chmod 777 /tmp/tpm  # Ensure proper permissions

swtpm socket --tpmstate dir=/tmp/tpm \
             --ctrl type=unixio,path=/tmp/swtpm-sock \
             --tpm2 --server type=tcp,port=2321 \
             --ctrl type=tcp,port=2322 \
             --flags startup-clear &

export TPM2TOOLS_TCTI="swtpm:port=2321"

