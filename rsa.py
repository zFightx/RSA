import random
import libnum
import math
import base64
import hashlib

## Alexandre Souza Costa Oliveira
## 170098168
##
##

# funcao responsavel por garantir probabilisticamente que o numero eh primo
def miller_rabin(n, k):
    # referencia: https://gist.github.com/Ayrx/5884790
    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification
    # If number is even, it's a composite number

    if (n == 1 or n == 2 or n == 3):
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Funcao geradora de numeros primos
def GerarNumeroPrimo():
    isPrimo = False

    while(not isPrimo):
        numero = random.getrandbits(512)

        isPrimo = miller_rabin(numero, 40)

    return numero

# Funcao geradora de Hash
def GerarHash(mensagem):
    hash = hashlib.sha3_256(mensagem.encode()).hexdigest()

    return hash

# Funcao de Parsing para Base64
def EncodeBase64(mensagem):
    base = base64.b64encode(str(mensagem).encode())

    return base

# Funcao inverso de Parsing para Base64
def DecodeBase64(objeto):
    mensagem = base64.b64decode(objeto)

    return mensagem

# Funcao que converte string em int
def StringBytesToInt(mensagem):
    mensagem_int = int.from_bytes(str(mensagem).encode(), 'big')
    return mensagem_int

# Funcao que converte Int para Bytes
def IntToBytes(mensagem):
    b = (mensagem).to_bytes(int(math.log(mensagem, 256)) + 1, byteorder='big')
    return b

# Funcao que cifra uma mensagem
def Cifrar(e, n, mensagem):
    cifrado = pow(StringBytesToInt(mensagem), e, n)
    
    return cifrado

# Funcao que verifica a hash
def VerificarHash(mensagem, hash):
    return GerarHash(mensagem) == hash

# Funcao que decifra uma mensagem
def Decifrar(d, n, cifrado):
    decifrado = pow(int(cifrado), d, n )
    return decifrado

# Funcao que le o arquivo texto.txt
def LerArquivo():
    file = open("texto.txt", "r")

    lines = file.readlines()

    return "".join(lines)

# Funcao main
def main():
    opcao = -1

    while (opcao < 0 or opcao > 2):
        print("O que voce deseja fazer?")
        print("")
        print("1- Cifrar RSA")
        print("2- Decifrar RSA")
        print("")

        opcao = int(input("Opcao: "))
        
    if(opcao == 1):
        p = GerarNumeroPrimo()
        q = GerarNumeroPrimo()
        n = p*q
        phi = (p-1)*(q - 1)
        e = 339225029003687
        d = libnum.invmod(e ,phi)

        mensagem = LerArquivo()

        print("Mensagem que sera cifrada: ", mensagem)
        print("")

        # Cria a hash para a mensagem
        hash = GerarHash(mensagem)
        print("Hash hex: ", hash)
        print("")

        # Cifra a mensagem e hash
        textoCifrado = Cifrar(e,n, mensagem)
        hashCifrado = Cifrar(e,n, hash)

        print("Texto Cifrado: ", textoCifrado)
        print("")
        print("Hash Cifrada: ", hashCifrado)
        print("")

        # Transforma em Base64
        preparo = "Texto:" + str(textoCifrado) + "Hash:" + str(hashCifrado)
        encoded = EncodeBase64(preparo)
        print("Base64: ", encoded.decode())
        print("")

        print("Chaves publica: ( n, e )")
        print("n : ", n)
        print("e : ", e)
        print("")
        print("Chaves privada: ( p, q, d )")
        print("p : ", p)
        print("q : ", q)
        print("d : ", d)
    
    else:
        n = int(input("Digite a chave publica n: "))
        d = int(input("Digite a chave privada d: "))

        # Destransforma da Base64
        print("Iniciando processo de decifrar")
        print("")

        encoded = LerArquivo()

        decoded = DecodeBase64(encoded).decode()
        decoded = decoded.replace("Texto:", "")
        decoded = decoded.split("Hash:")

        # Decifra o Texto
        textoDecifrado = IntToBytes(Decifrar(d, n, decoded[0])).decode()
        print("Texto Decifrado: ", textoDecifrado)
        print("")
        
        #Decifra a Hash
        hashDecifrado = IntToBytes(Decifrar(d, n, decoded[1])).decode()
        print("Hash Decifrada: ", hashDecifrado)
        print("")

        # Verificando Assinatura
        print("Verificando Hash")
        if(VerificarHash(textoDecifrado, hashDecifrado)):
            print("A verificacao foi concluida com sucesso, autenticidade comprovada.")
        else:
            print("A verificacao falhou, a hash nao corresponde a mensagem.")
        

main()