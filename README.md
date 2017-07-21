README
--

@brief _Informações gerais sobre o programa_

Projeto da disciplina **IMD0703 Segurança de Redes**, ministrada pelo Prof. Silvio Sampaio no curso BTI da UFRN.


Programa
--

_Software Guard - File Authentication using HMAC_


Objetivo
--

- Este projeto tem como objetivo a **implementação de um programa de guarda de arquivos** de um determinado diretório utilizando HMAC (Hash-based Message Authentication Code).


Orientações sobre o funcionamento
--

- Informe uma opção e um diretório:
	- -i 	para iniciar a guarda do diretório
	- -t 	para rastrear o diretório
	- -x 	para desativar a guarda do diretório
- Exemplo: `./guard.py <option> <folder_path>`


Observações sobre a implementação
--

- A função hash padrão utilizada é MD5. Porém, a classe HMAC.py está preparada para funcionar com SHA1, SHA224, SHA256, SHA384 e SHA512:
	- Para isso, basta instanciar a classe passando ao método construtor a chave e a função que deve ser utilizada, por exemplo: `obj = HMAC("key", "sha512")`
