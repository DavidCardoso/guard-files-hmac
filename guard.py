#!/usr/bin/env python
# -*- coding: utf-8 -*-

##	@file 		guard.py
#	@brief 		Programa Guarda.
#	@details 	Usando cálculo de HMAC, permite garantir a autenticação 
#				de um conjunto de arquivos para uma determinada pasta (recursivamente).
#	@since		09/10/2016
#	@date		14/10/2016
#	@author		David
#	@copyright	2016 - All rights reserveds
#	@sa 		http://projetos.imd.ufrn.br/davidcardoso-ti/imd0703/blob/master/hmac/guard.py

import os, sys			# os, sys 		- recursos de sistema
import shutil 			# shutil 		- operações avançadas de sistema
import mmap 			# mmap 			- suporte à arquivo em memória

from collections import OrderedDict		# OrderedDict 	- dicionário ordenado
from datetime import datetime			# datetime 		- data e tempo
from string import split 				# split 		- separar strings de acordo com separador
from HMAC import HMAC 					# HMAC 			- classe para cálculo HMAC (Hash-based Message Authentication Code)


"""Variáveis"""
## negrito
BOLD 		= '\033[1m'
## cor padrão para impressões no terminal		
NORMAL 		= '\033[0;0m'		
## cor verde para destacar impressões no terminal
GREEN 		= BOLD+'\033[32m'	
## cor azul para destacar impressões no terminal
BLUE 		= BOLD+'\033[34m'	
## cor branca para destacar impressões no terminal
WHITE 		= BOLD+'\033[37m'	
## cor amarela para destacar impressões no terminal
YELLOW 		= BOLD+'\033[93m'	
## cor vermelha para destacar impressões no terminal
RED 		= BOLD+'\033[91m' 

## quebra de linha
ENDL 		= "\n"
## tabulação	
TAB 		= "\t"
## separador CSV	
SEP 		= ";" 
## objeto da classe HMAC	
HMAC_OBJ 	= HMAC()
## dicionário para armazenar os HMACS dos arquivos
MATCHES 	= {}
## opção de ação do programa (-i, -t ou -x)		
ARG_OPTION  = ""
## diretório a ser aplicado a ação	
ARG_PATH 	= ""
## diretório oculto para armazenar arquivos de rastreamento contendo o HMAC dos arquivos
HIDDEN 		= ".guard"
## nome do arquivo de rastreamento
TMP 		= datetime.now().strftime('%Y%m%d%H%M%S')
## extensão do arquivo de rastreamento
EXT 		= ""



## 	@brief 		Função para limpar console
def clearConsole():
	os.system('cls' if os.name == 'nt' else 'reset')


## 	@brief 		Função printExampleArgs()
# 	@details 	Imprimir explicação dos argumentos via linha de comando
def printExampleArgs():
	print '%sGive an option and a folder:%s' 				% (ENDL, ENDL)
	print '-i %sto start folder guard%s' 					% (TAB, ENDL)
	print '-t %sto track the folder%s' 						% (TAB, ENDL)
	print '-x %sto stop folder guard%s' 					% (TAB, ENDL)
	print 'Example: ./guard.py <option> <folder_path> %s' 	% (ENDL)
	print 'Ending... %s' 									% (ENDL)


## 	@brief 		Função checkArgs()
# 	@details 	Validação dos argumentos passados via linha de comando
def checkArgs():
	global ARG_OPTION, ARG_PATH
	if sys.argv.__len__() == 3:
		ARG_OPTION 	= str(sys.argv[1])
		ARG_PATH 	= str(sys.argv[2])
		if ARG_OPTION not in ('-i', '-t', '-x'):
			print 'Invalid option!%s' % (ENDL)
			printExampleArgs()
			sys.exit()
	else:
		print 'Expected 2 arguments but %i was given!%s' % (sys.argv.__len__()-1, ENDL)
		printExampleArgs()
		sys.exit()


## 	@brief 		Função genHMAC()
# 	@details 	Gera HMAC dos arquivos do diretório de forma recursiva
# 	@param 		dir - caminho do diretório
def genHMAC(dir):
	global MATCHES
	# mudando diretorio
	os.chdir(dir)
	# caminho absoluto para diretorio
	dir = os.getcwd()

	# se existe pasta oculta
	if HIDDEN in os.listdir(dir):
		# percorre recursivamente todos os subdiretórios
		for root, dirnames, filenames in os.walk(dir):
			# percore todos os arquivos dos subdiretórios
			for filename in filenames:
				# ignora a pasta oculta
				if root[-len(HIDDEN):] != HIDDEN:
					# caminho completo
					fullpath_filename = os.path.join(root, filename)
					# abre arquivo e lê conteúdo
					f = open(fullpath_filename, "r")
					if f:
						content = f.read()
						f.close()
						# objeto HMAC - submete CAMINHO + CONTEUDO
						h = HMAC_OBJ.hmac(fullpath_filename+content)
						# adiciona caminho absoluto do arquivo e seu respectivo HMAC ao dicionário
						MATCHES.update( {fullpath_filename : h.hexdigest()} )
					else:
						MATCHES.update( {fullpath_filename : 'Error trying to open file!'} )

		# ordenar dicionário por chave (fullpath_filename)
		MATCHES = OrderedDict(sorted(MATCHES.items(), key=lambda t: t[0]))

		# Diretório inválido ou arquivos inexistentes
		if MATCHES.__len__() == 0:
			print 'Invalid folder or there are no files in the folder!%s' % (ENDL)
			printExampleArgs()
			sys.exit()
	else:
		print "%sFolder '%s' not found! You need to start folder guard: %s" % (ENDL, HIDDEN, os.getcwd())
		printExampleArgs()
		sys.exit()
		
			
## 	@brief		Função printHMAC()
# 	@details 	Imprimir dicionário contendo os arquivos e os respectivos HMACs	
# 	@param 		dir - caminho do diretório
def printHMAC(dir):
	# mudando para dir
	os.chdir(dir)
	# imprimir conteúdo do dicionário
	for hash, filename in MATCHES.iteritems():
		print hash+TAB+filename
	# diretorio atual
	print "%sFiles of the folder has been printed: %s" % ( ENDL, os.getcwd() )


## 	@brief 		Função startGuard()
# 	@details 	Iniciar a guarda do diretório
# 	@param 		dir - caminho do diretório
def startGuard(dir):
	# mudando para dir
	os.chdir(dir)
	# cria pasta oculta se não existir
	if HIDDEN not in os.listdir(dir):
		print "%sEnabled folder guard: %s" % ( ENDL, os.getcwd() )
		# cria pasta oculta
		os.mkdir(HIDDEN)
		# mudando para pasta oculta
		os.chdir(HIDDEN)
		# gerar dicionário com os HMACs
		genHMAC(dir)
		# gerar arquivo de rastreio
		createTrackFile(dir)
	else:
		print "%sFolder already guarded: %s" % ( ENDL, os.getcwd() )


## 	@brief		Função createTrackFile()
# 	@details 	Criar arquivo de rastreio contendo os arquivos e os respectivos HMACs
# 	@param 		dir - caminho do diretório
def createTrackFile(dir):
	
	# se existe pasta oculta
	if HIDDEN in os.listdir(dir):
		# mudando para pasta oculta
		os.chdir(dir+'/'+HIDDEN)
		print "%sGenerating new tracking file: %s" % ( ENDL, TMP+EXT )
		# salva dados do dicionário no arquivo de rastreio
		track_file = open(TMP+EXT, "w+")
		if track_file:
			for filename, hash in MATCHES.iteritems():
				track_file.write( str(hash+SEP+filename+ENDL) )
			track_file.close()
			print "%sTracking file saved in: %s" % ( ENDL, os.getcwd() )
		else:
			print "%sError trying to generate tracking file!" % (ENDL)
	else:
		print "%sFolder '%s' not found! You need to start folder guard: %s" % (ENDL, HIDDEN, os.getcwd())
		printExampleArgs()


## 	@brief 		Função stopGuard()
# 	@details 	Finalizar a guarda do diretório
# 	@param 		dir - caminho do diretório
def stopGuard(dir):
	# apaga o diretório oculto e seus arquivos de rastreio
	if HIDDEN in os.listdir(dir):
		# mudando para dir
		os.chdir(dir)
		# caminho absoluto da pasta oculta
		path_del = os.getcwd()+'/'+HIDDEN
		# apaga
		shutil.rmtree(path_del)
		print "%sDisabled folder guard: %s" % ( ENDL, os.getcwd() )
	else:
		print "%sFolder '%s' not found! You need to start folder guard: %s" % (ENDL, HIDDEN, os.getcwd())
		printExampleArgs()


## 	@brief 		Função checkChanges()
# 	@details 	Verifica as alterações no diretório guardado
# 	@param 		dir - caminho do diretório
# 	@param 		hid - pasta oculta
def checkChanges(dir, hid):
	# muda e seleciona caminho absoluto da pasta oculta
	if hid in os.listdir(dir):
		path = dir+'/'+hid
		os.chdir(path)
		path = os.getcwd()
	
		# seleciona último arquivo de rastreio
		track_files = sorted(os.listdir(path))
		if track_files.__len__() > 1:
			last_track 	=  track_files[-1]
		elif track_files.__len__() == 1:
			last_track 	=  track_files[0]
		else:
			last_track	= False

		# compara último arquivo de rastreio com situação atual do diretório guardado
		if last_track:
			print "%sComparing with the last tracking file: %s" % ( ENDL, last_track )

			# abre último arquivo de rastreio
			f = open(last_track, 'r')
			# otimiza busca no arquivo em memória com o módulo mmap
			s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

			# verifica: novos, modificados e não-modificados
			count = 1
			okay  = 0
			for filename, hash in MATCHES.iteritems():
				if   s.find(filename) != -1 and s.find(hash) == -1:
					print "(%s) %s %s%s" 		% (str(count).zfill(4), RED+'Changed'+NORMAL, TAB, filename)
					count += 1
				elif s.find(filename) == -1 and s.find(hash) == -1:
					print "(%s) %s %s%s" 		% (str(count).zfill(4), GREEN+'New'+NORMAL, TAB, filename)
					count += 1
				elif s.find(filename) != -1 and s.find(hash) != -1:
					# print "(%s) %s %s%s" 		% (str(count).zfill(4), BLUE+'Okay'+NORMAL, TAB, filename)
					okay += 1

			# verifica: excluídos
			for line in f.readlines():
				exploded = split(line, ';')
				if exploded[1][0:-1] not in MATCHES.keys():
					print "(%s) %s %s%s" 		% (str(count).zfill(4), YELLOW+'Deleted'+NORMAL, TAB, exploded[1][0:-1])
					count += 1

			# imprime qtd de arquivos não-modificados
			if okay > 0:
				print "%s%s file(s) %s!" % (ENDL, BLUE+str(okay)+NORMAL, BLUE+'Okay'+NORMAL)
		
			s.close()
			f.close()
		else:
			print "%sEmpty folder: %s" % (ENDL, path)



# BLOCO PRINCIPAL DO PROGRAMA
if __name__ == "__main__":

	# limpar console
	clearConsole()

	print "%s==> Software Guard" % (WHITE)
	print "    File Authentication using HMAC.%s%s" % (ENDL, NORMAL)

	# validar argumentos
	checkArgs()

	# imprimir
	#printHMAC(ARG_PATH)

	# iniciar guarda no diretório
	if   ARG_OPTION == '-i':
		startGuard(ARG_PATH)
	# rastrear diretório
	elif ARG_OPTION == '-t':
		genHMAC(ARG_PATH)
		checkChanges(ARG_PATH, HIDDEN)
		createTrackFile(ARG_PATH)
	# desativar guarda no diretório
	elif ARG_OPTION == '-x':
		stopGuard(ARG_PATH)

	sys.exit()