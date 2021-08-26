openssl req -config test.local.conf -new -sha256 -newkey rsa:2048 -nodes -keyout private.key -x509 -days 365 -out localhost.crt
openssl rsa -in private.key -out private.pem
openssl rsa -in private.pem -pubout -out public.pem