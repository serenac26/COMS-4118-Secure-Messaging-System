openssl genrsa -aes256 -passout pass:$2 -out $1 2048
chmod 600 $1