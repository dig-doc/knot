#!/usr/bin/env bash

set -e

gitroot=$(git rev-parse --show-toplevel)
tls_certificate_conf=$(cat <<EOF
{
	"cert-file": "$gitroot/modules/http/test_tls/test.crt",
	"key-file": "$gitroot/modules/http/test_tls/test.key"
}
EOF
)

# configure TLS certificate files
kresctl config set -p /network/tls "$tls_certificate_conf"
if [ "$?" -ne "0" ]; then
	echo "Could not set TLS certificate files."
	exit 1
fi
