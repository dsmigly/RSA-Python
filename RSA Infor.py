# -*- coding: utf-8 -*-
"""

@author: Bruno Henrique Michelin Silva    RA: 081160030
         Douglas de Araujo Smigly         RA: 081160008
         Gileade Lamede Martins           RA: 081160044
         
"""
import binascii
 
import random

from Crypto.Util import number

'''
    Calcula a função Phi de Euler para n, que nesse caso é produto de
    dois primos p e q. Pelo Teorema de Euler, devemos retornar
    p*q*(1-1/p)*(1-1/q)=(p-1)*(q-1)

'''
def EulerPhi(p,q):
    return (p-1)*(q-1)


def mdc(x,y):
    x = abs(x) ; y = abs(y)
    while x > 0:
        x, y = y % x, x
    return y


'''
retorna um elemento e em PHI(num), lembrando aqui que 
phi(num) = |PHI(num)|.

A chave pública
'''
def chave_publica(num): 
    for e in range(3, num, 2):
        if(mdc(num,e) == 1):
            return e

'''
Encontra o inverso de u em Z/vZ = {0,1,2,...,v2,v-1}
'''
def inverso(u, v):

    u3, v3 = int(u), int(v)
    u1, v1 = 1, 0
    while v3 > 0:
        q=divmod(u3, v3)[0]
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1<0:
        u1 = u1 + v
    return u1

'''
Calcula a chave privada
'''
def chave_privada(e,phi):
    return inverso(e,phi)


bits = 2048
    
p = number.getPrime(bits) #primeiro primo
q = number.getPrime(bits) #segundo primo
n = p * q
Phi_n = EulerPhi(p,q) # Função Phi de Euler para n=p*q
e = chave_publica(Phi_n) # gera e para a chave pública
chave_publica = (n,e)
d = chave_privada(e,Phi_n)
  
mensagem = 'The information security is of significant importance to ensure the privacy of communications'
print('Mensagem                        ', mensagem)
 
dados_hexadecimal = binascii.hexlify(mensagem.encode())
print('dados hexadecimal               ', dados_hexadecimal)
 
textoNumerico = int(dados_hexadecimal, 16)
print('texto numerico                  ', textoNumerico)
 
if textoNumerico > n:
  raise Exception('texto é muito grande para a chave')

print('Chave pública e:                ', e)
print('Chave privada d:                ', d)

texto_criptografado = pow(textoNumerico, e, n)
print('texto numerico criptografado    ', texto_criptografado)

texto_descriptografado = pow(texto_criptografado, d, n)
print('texto numerico descriptografado ', texto_descriptografado)
 
print('Mensagem original               ', binascii.unhexlify(hex(texto_descriptografado)[2:]).decode())

