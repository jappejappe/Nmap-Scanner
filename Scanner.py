import nmap
import nvdlib
import subprocess
from re import split as re_split
from copy import copy
'''importa as bibliotecas'''



FLAGS = ("") # Flags que serão adicionadas no comando
NUMBEROFCPE = (1)
#cores do texto do terminal:
DEFAULT = ("\x1b[0m")
WHITE = ("\033[37m")
RED = ("\033[31m")
GREEN = ("\033[32m")
YELLOW = ("\033[33m")
BOLD = ("\033[1m")


nm = nmap.PortScanner() # cria uma instância de "nmap.PortScanner" 
nm.scan(input(f"{YELLOW}IP:{DEFAULT} "), input(f"{YELLOW}Portas:{DEFAULT} ")) # solicita as informações do host que serão escaneadas no NMAP, o que permite atualizar os atributos da instância
cl = nm.command_line() # gera o comando para ser executado no NMAP
cl = cl.replace("-oX - ", FLAGS) # corrige o comando acima, substituindo o primeiro parâmetro pela "FLAGS"

outputr = subprocess.getoutput(cl) # executa o comando gerado no terminal

output = outputr[outputr.index("SERVICE")-1:] #corta a string a partir da primeira palavra "SERVICE"
output = output[:output.rfind("Service")-1] #corta a string até a última palavra "Service"
output = list(filter(None, re_split(r"     | ", output))) #cria uma lista com cada palavra do resultado do nmap



portData = dict() #define o dicionário

'''
estado das portas
0 = closed
1 = filtered
2 = open
'''



for w in range(len(output)): # conta por índice cada item na lista
    PORTSTATUS = ["closed", "filtered", "open"] # possíveis status das portas
    currentPort = PORTSTATUS.index(output[w]) if output[w] in PORTSTATUS else -1 # verifica se tal palavra refere-se ao estado da porta
    
    # cria as variáveis de cada porta:
    port = None
    protocol = None
    status = None
    service = None
    version = None

   
    if currentPort != -1: # confere se o status da porta é válido
        port = int(re_split(r"\n|/", output[w-1])[1])
        protocol = re_split(r"\n|/", output[w-1])[2]

    try:
        if currentPort == 0: # se a porta estiver fechada, salva só o status
            status = output[w] 

        if currentPort == 1: # se a porta estiver filtrada, salva status e serviço
            status = output[w] 
            service = output[w+1].re_split("\n")[0]

        if currentPort == 2: # se a porta estiver aberta, salva tudo
            status = output[w] 
            service = output[w+1]
            for b in range(w+2, w+12): # busca uma quebra de linha nas próximas 10 palavras
                z = output[b].find("\n") # busca o caractere final do nome da versão
                if z != -1:
                    version = " ".join(output[w+2: b])+" "+output[b][0:z] #  concatena as palavras da versão até "\n"
                    w = copy(b) # pula o contador para a próxima linha da lista
                    break
                
    except: 
        print(f"\tUm erro aconteceu na porta {port}")

    if currentPort !=-1: # se a porta é válida, cria um dicionário por porta, tendo o número como chave
        portData[port] = { 
            "PROTOCOL": protocol, 
            "STATUS": status,
            "SERVICE": service,
            "VERSION": version,
            #"versionSimplified": re_split(" ", version)[0]+(" ")+re_split(" ", version)[1] #simplifica o nome da versão para buscar com mais facilidade
        }

for k,v in portData.items(): # printa o dicionário formatado
    print(f"    {k}: {v}\n")

cpeSearchport = int(input("Porta que deseja analisar o CPE: "))
cpeFinded = None

for l in range(len(portData[cpeSearchport]["VERSION"]), 0, -1): # faz um contador decrescente do índice do "versionsimplified"
    cpeFinded = nvdlib.searchCPE(
        keywordSearch = portData[cpeSearchport]["VERSION"][:l],
        limit = NUMBEROFCPE,
        key='bc208db3-5fd1-4ebc-8a6b-fe9d6cd7a434'
    ) # faz a busca com o nvdlib, e encontra a versão mais próxima

    if l<4:
        print(f"\tCaracteres insuficientes para buscar")
        break
    if len(cpeFinded)>0:
        print(f"\t{GREEN}Encontrado em: {DEFAULT}{portData[cpeSearchport]['VERSION'][:l]}")
        break
    print(f"\t{RED}Não encontrado em: {DEFAULT}{portData[cpeSearchport]['VERSION'][:l]}")

for eachCPE in cpeFinded:
    print(f"\n{YELLOW}Buscando por:{DEFAULT}", eachCPE.cpeName)

cveFinded = nvdlib.searchCVE(
    cpeName = (cpeFinded[0].cpeName),
    limit = NUMBEROFCPE,
    key='bc208db3-5fd1-4ebc-8a6b-fe9d6cd7a434',
)

print("ID:", cveFinded[0].id)
print("Risco:", cveFinded[0].v2severity)
print("Descoberta:", cveFinded[0].published)
print("Última modificação:", cveFinded[0].lastModified)
print("Descrição:", cveFinded[0].descriptions)
print("Explorabilidade:", cveFinded[0].v2exploitability,"/ 10.0")
print("Complexidade de acesso:", cveFinded[0].v2accessComplexity)

##### Busca dos CPEs e CVEs #####

