# dccnet

## usage

- Start the server

		python dccnet.py -s <port> <input_file> <output_file>


- Start the client

		python dccnet.py -c <server_ip>:<server_port> <input_file> <output_file>

## known issues

|Issue|Fix|
|---|---|
|"O programa dele funciona parcialmente. Esses caracteres espúrios podem ser do cabeçalho que ele não está removendo, provavelmente. Considere que ele funciona full duplex mas deduza alguns pontos (entre 2,5 e 5, a seu critério, dependendo do que você julgar mais justo pelo que ele fez e os outros fizeram) por haver erro no conteúdo recebido. Veja também a questão da terminação que, pelo que entendi, não foi implementada corretamente."||
