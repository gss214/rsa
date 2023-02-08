# Projeto 2 de Segurança Computacional 2022.2
Projeto 2 da disciplina de Segurança Computacional da UnB em 2022.2. \
Universidade de Brasília, Instituto de Ciências Exatas, Departamento de Ciência da Computação. \
Desenvolvido por: [Guilherme Silva Souza](https://github.com/gss214) e [Maria Eduarda Machado de Holanda](https://github.com/dudaholandah) \
Linguagem utilizada: Python.

## Descrição

O trabalho consiste em implementar um gerador e verificador de assinaturas RSA em arquivos, com as seguintes funcionalidades: 

1. Parte I: Geração de chaves e cifra \
  a. Geração de chaves (p e q primos com no mínimo de 1024 bits) \
  b. Cifração/decifração assimétrica RSA usando OAEP. 

2. Parte II: Assinatura \
  a. Cálculo de hashes da mensagem em claro (função de hash SHA-3)  \
  b. Assinatura da mensagem (cifração do hash da mensagem) \
  c. Formatação do resultado (caracteres especiais e informações para verificação em BASE64) 

3.  Parte III: Verificação: \
  a. Parsing do documento assinado e decifração da mensagem (de acordo com a formatação usada, no caso BASE64) \
  b. Decifração da assinatura (decifração do hash) \
  c. Verificação (cálculo e comparação do hash do arquivo)
  
 ## Rodando o projeto
 
 Para rodar o projeto é preciso ter o Python instalado na máquina, assim como as bibliotecas importadas. Utilizamos a versão 3.10.4. Depois é só rodar o comando `python main.py` ou `python3 main.py`
