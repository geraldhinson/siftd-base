openssl req -x509 -nodes -days 365 \
  -newkey rsa:4096 \
  -keyout ../localhost-server.key \
  -out ../localhost-server.crt \
  -config localhost-san.cnf \
  -extensions req_ext
