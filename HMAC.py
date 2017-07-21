#!/usr/bin/env python
# -*- coding: utf-8 -*-

##	@file 		HMAC.py
#	@brief 		Classe HMAC.
#	@details 	Gera um MAC de um arquivo ou dado baseado em uma Função Hash.
#	@since		09/10/2016
#	@date		14/10/2016
#	@author		David
#	@copyright	2016 - All rights reserveds
#	@sa 		http://projetos.imd.ufrn.br/davidcardoso-ti/imd0703/blob/master/hmac/HMAC.py

import hashlib 		# hashlib 	- algoritmos seguros de hash (MD5, SHA1, SHA224, SHA256, SHA384, SHA512)

class HMAC(object):
	
	## 	@brief Método construtor
	#   @details Inicializa váriaveis
	# 	@param k 	- chave a ser usada no cálculo
	#   @param f 	- função hash
	def __init__(self, k=False, f=False):
		super(HMAC, self).__init__()
		## chave usada no cálculo HMAC
		self.__key 	= k if k else "e2a46e842e3019ac9308bf5e8b68892c"
		## função hash usada no cálculo HMAC
		self.__func = f if f else "md5"
	
	## 	@brief 		Método select_hash()
	# 	@details 	Seleciona uma função hash a ser usada no cálculo HMAC
	# 	@return 	Lista de três objetos de acordo com a função hash escolhida
	def select_hash(self):
		if   self.__func == "md5":
			return ( hashlib.md5(), hashlib.md5(), hashlib.md5() )
		elif self.__func == "sha1":
			return ( hashlib.sha1(), hashlib.sha1(), hashlib.sha1() )
		elif self.__func == "sha224":
			return ( hashlib.sha224(), hashlib.sha224(), hashlib.sha224() )
		elif self.__func == "sha256":
			return ( hashlib.sha256(), hashlib.sha256(), hashlib.sha256() )
		elif self.__func == "sha384":
			return ( hashlib.sha384(), hashlib.sha384(), hashlib.sha384() )
		elif self.__func == "sha512":
			return ( hashlib.sha512(), hashlib.sha512(), hashlib.sha512() )
		else:
			return ( False, False, False )
	# end select_hash()
	

	## 	@brief 		Método hmac()
	# 	@details 	Calcula o MAC (Código de Autenticação de Mensagem) usando Funções de Hash
	# 	@param 		msg - mensagem usada para produzir o HMAC
	# 	@return 	objeto hash
	def hmac(self, msg):
		pw = False
		while not pw:
			(pw, second_part, hash) = self.select_hash()
			if not pw:
				self.__func = raw_input("==> Escolha uma função hash válida!\n    md5, sha1, sha224, sha256, sha384 ou sha512\n")

		trans_5C 	= "".join(chr(x ^ 0x5c) for x in xrange(256))
		trans_36 	= "".join(chr(x ^ 0x36) for x in xrange(256))
		blocksize 	= pw.block_size

		key = self.__key
		if len(key) > blocksize:
			key = pw.update(key).digest() # limita o tamanho da chave até o tamanho blocksize

		key 		+= chr(0) * (blocksize - len(key)) # padding com zeros à direita
		o_key_pad 	 = key.translate(trans_5C)
		i_key_pad 	 = key.translate(trans_36)

		second_part.update(i_key_pad + msg)
		hash.update(o_key_pad + second_part.digest())

		return hash
	# end hmac()


# TESTES
# if __name__ == "__main__":
# 	mac1 = HMAC("key", "")
# 	h = mac1.hmac("The quick brown fox jumps over the lazy dog")
# 	print h.hexdigest()  # 80070713463e7749b90c2dc24911e275

# 	mac2 = HMAC("80070713463e7749b90c2dc24911e275", "")
# 	h2 = mac2.hmac("password")
# 	print h2.hexdigest()  # e2a46e842e3019ac9308bf5e8b68892c