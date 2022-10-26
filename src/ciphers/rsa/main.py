#As variaveis "p" e "q" receberam 2 valores primos gerados aleatórios

p = 164135779097971035236649394475230357278124915621463293023273902303843044950480319453250999410547280560670263768266230090357428490127143984896307355671461126842835184246788114540659957680623493680565155659511124829731008615236795830881171750793725202846786842109262329001165158003382102429709172276498886649237
q = 165389069375624129124577679709984943001855396081760280865108442322540011434157863851597806985830199973407482928708466843496515818984177087383252332296569666141995823588509348478221423227524702243540578982478075990264543614670612433554095388893676099391497610075467259800940201232785702162863296854607662897521


    

# Aqui foi implementado um método que descobre o maior divisor comum entre dois números.

def computeGCD(x, y):
    if x > y:
        small = y
    else:
        small = x

    for i in range(1, small+1):
        if((x % i == 0) and (y % i == 0)):
            resu = i

    return resu


# Compute a função totiente phi(n) = (p -1) (q -1)
def totientePhi():
    return (p - 1) * (q - 1)


# utilizado para encontrar os valores que são primos entre si
# isso faz parte do algoritimo.
# Escolha um inteiro  "e"  , 1 < "e" < phi(n) ,  "e" e phi(n) sejam primos entre si.


def primosEntreSi(m):
    e = 3
    while computeGCD(e, m) > 1:
        e += 2
    return e

# Esse método foi implementado para fazer o mod inverso

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1

    if (m == 1):
        return 0

    while (a > 1):

        # q é quociente

        q = a // m
        t = m
        # m é resto agora, processo # igual ao algoritmo de Euclides
        m = a % m
        a = t
        t = y

        # Atualiza x e y
        y = x - q * y
        x = t

    # Torna x positivo
    if (x < 0):
        x = x + m0

    return x


n = p * q
n = p * q  # isso faz parte do algoritimo
m = totientePhi()  # utilização da Função totiente de Euler
e = primosEntreSi(m)  # tira os primos entre eles
d = modInverse(e, m)  # faz o mod inverso

# exibe os valores na tela
# print("p: {}".format(p))  # valor primo
# print("q: {}".format(q))  # valor primo
# Utilizado em conjunto com as chaves publica e privada
# print("n: {}".format(n))
# print("e: {}".format(e))  # A chave pública: o par (n,e)
# print("d: {}".format(d))  # chave privada: a tripla (p,q,d)

# Converte numero decimal em um valor binario exemplo: (exemplo: 198 -> 11000110)
def getBinaryOfNumber(vlr):
    return "{0:08b}".format(vlr)


print("\n\n")

# mensagem cifrada - RSA_encrypt()


def mensagemCifrada(mensagem):
    converteAscii = [ord(letra) for letra in mensagem]   
    print("Valores da tabela ASCII: ", converteAscii)

    #function ord() retorna o código Unicode de um determinado caractere
    #Unicode - Padrão universal de codificação de caracteres
    # Esta convertendo o texto para uma lista de valores da tabela ascii
    # e convertendo os valores numericos para suas forma binarias (exemplo: 198 -> 11000110)
    # Após isso todos os valores da lista são unidos formando um unico valor binario(exemplo: 198 -> 11000110; 153 -> 10011001; FICA: 1100011011000110)
    # Após isso o valor binario é convertido para o seu equivalente do tipo decimal. (exmp: 1100011011000110 -> 50886 )
    decimalFromBinary = int(
        "".join([getBinaryOfNumber(ord(l)) for l in mensagem]), 2)

    # Aqui foi  utilizando o método proprio do python para fazer a exponenciação de um numero e
    # tirar o mod do valor. Como os valores eram extremamente grandes não foi possivel utilizar um método implementado por conta propria.
    # Faz parte do algoritimo para encriptografar
    msgcifrada = pow(decimalFromBinary, e, n)

    #A função python pow() retorna o resultado do primeiro parâmetro elevado a potência do segundo parâmetro, o terceiro parâmetro executa módulo de mod no resultado do primeiro e segundo parâmetro .

    return msgcifrada


print("\n\n")


# mensagem decifrada - RSA_encrypt()
def mensagemDecifrada(mensagem):
    # Faz parte do algoritimo para desincriptografar
    mensagem = pow(mensagem, d, n)

    # Aqui está convertendo um valor decimal para a sua forma binaria.
    binaryFromDecimal = "{0:08b}".format(mensagem)

    # aqui está verificando se tamanho do número é divisivel por 8. Caso não seja é adicionado
    # 0 no inicio do número até que ele seja divisivel por 8
    while len(binaryFromDecimal) % 8 != 0:
        binaryFromDecimal = "0{}".format(binaryFromDecimal)

    # Aqui está quebrando a string em blocos de 8 em um array onde cada posição tem uma string de 0 e 1 referente a um caractere.
    # Esse valor 8 é equivalente a 1 byte de 8 bits.
    # Exemplo (01000001 -> 65)
    arraDeBits = [int(binaryFromDecimal[i*8:8*(i+1)], 2)
                  for i, _ in enumerate(range(int(len(binaryFromDecimal)/8)))]

    # Aqui está exibindo cada valor referente da tabela ASCII
    # Aqui está convertendo cada valor numerico da tabela ASCII para sua forma de caracteres, unindo um array de string.
    resu = "".join([chr(caractere) for caractere in arraDeBits])

    return resu

# print(30*"=")
# opcao = int(input("Digite 1 para Criptografar:\nDigite 2 para Descriptografar:\n"))

# if opcao == 1:
#     print(60*"=")
#     print("Mensagem Cifrada: ", mensagemCifrada(input("Digite sua mensagem: ")))
#     print(60*"=")
# else:
#     print(60*"=")
#     print("Mensagem Decifrada: ", mensagemDecifrada(
#         int(input("Digite sua sua mensagem Cifrada: "))))
#     print(60*"=")