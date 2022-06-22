### Nom: Traboulsi Rawan
### TP RS40 SANS BONUS 
###APPLICATION RSA

import hashlib
import binascii

def home_mod_expnoent(x,y,n):                               
     y=format(y, 'b')   #on transforme en binaire l'exposant 
     k=(len(y)) #longueur du bit
     R1=1       
     R2=x
     result=[]
     for i in range(0, len(y), 1):
        result.append(int(y[i : i + 1]))     # stockage des bits de manière séparée dans un tableau
     for i in range(k-1,-1,-1):     # attention ici on dit qu'on part de k-1 jusqu'a -1 car si on met 0, le 0 ne sera pas pris en compte, le troisième paramètre indique la décrementation de -1
         if result[i]==1:           #si le bit est égale à  1  
             R1=(R1*R2)%n           # R1 prend la valeur de R1 multiplié par R2 si le bit est 1 si non on ne touche pas à R1
         R2=(R2*R2)%n               #R2 change  de valeur quelque soit la valeur du bit 0 ou 1
     return R1

def home_ext_euclide(y, b):  # algorithme d'euclide  pour la recherche de l'exposant secret
    (r,nouvr,t,nouvt)=(y,b,0,1)
    while nouvr>1:
        quotient=r//nouvr
        (r, nouvr) = (nouvr, r-quotient*nouvr)
        (t, nouvt) = (nouvt, t-quotient*nouvt)
    return nouvt%y

def home_pgcd(a,b): #recherche du pgcd
    if(b==0): 
        return a 
    else: 
        return home_pgcd(b,a%b)

def home_string_to_int(x): # pour transformer un string en int
    z=0
    for i in reversed(range(len(x))):
        z=int(ord(x[i]))*pow(2,(8*i))+z
    return(z)


def home_int_to_string(x): # pour transformer un int en string
    txt=''
    res1=x
    while res1>0:
        res=res1%(pow(2,8))
        res1=(res1-res)//(pow(2,8))
        txt=txt+chr(res)
    return txt

def home_crt(x, d, n, p, q):
    inverse_de_q = home_ext_euclide(q,1)
    dq = home_mod_expnoent(d,1,q-1)
    dp = home_mod_expnoent(d,1,p-1)
    mq = home_mod_expnoent(x,dq,q)
    mp = home_mod_expnoent(x,dp,p)
    h = home_mod_expnoent(((mp-mq)*inverse_de_q),1,p)
    return home_mod_expnoent(mq+ h*q,1,n)



def longueurMaximale(x1,x2): #entrer le secret
    i=1
    while(2**i<=(x1*x2)):
        i=i+1
    nbCaracteresMaxi= int (i/8)
    secret=input("donner un secret de "+str(nbCaracteresMaxi) + " caractères au maximum : ")
    while(len(secret)>i):
        secret=input("c'est beaucoup trop long,"+str(nbCaracteresMaxi)+" caractères S.V.P : ")
    return secret

#voici les éléments de la clé d'Alice  
x1a= 4579820294496290566294969699809179874954291492558650031115545248910313994426040028848491681624995341564243828102105735858449709249024645149039079851615068672131485973380655892429642294078197066544622274702182441696739748101961584299142062895758170049754613210002289847095132424311#p de taille 280
x2a= 3020783122158205543742926194441320592042356674306616602052178344474376153262617003554052013674466240354571677817499906055825154059129054286640435594755487330077663005776387848081910541912593238389796325736277013510055874948730636899295611832826110535344102322265653104234805037967#q de taille 280
na=x1a*x2a  #n
phia=((x1a-1)*(x2a-1))//home_pgcd(x1a-1,x2a-1)
ea=65537 #exposant public
da=home_ext_euclide(phia,ea) #exposant privé

#voici les éléments de la clé de bob
x1b= 8610985679681430616926021893747138443824010330718048183779571263263525671525081266775017713055060745253542227758211833362851490526750605172465070596014447648680858513989137020867878628364013379550574970083390110293158279364700437497071608960490009996623485068359713188627249683663#p de taille 280
x2b= 6771155409740451518708999410345775596372477593186690236955783873491879476739626137086602036753225005578597508795775107885908190275981256981714809515004255842770579846147340450394754914720071397833514063688597373023279877319109730122744057783433727188034849848510417313950315953049#q de taille 280
nb=x1b*x2b # n
phib=((x1b-1)*(x2b-1))//home_pgcd(x1b-1,x2b-1)
eb=65537 # exposants public         //on change l'exposant public 
db=home_ext_euclide(phib,eb)        #exposant privé



print("Vous êtes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre clé publique que tout le monde a le droit de consulter")
print("n =",nb)
print("exposant :",eb)
print("voici votre précieux secret")
print("d =",db)
print("*******************************************************************")
print("Voici aussi la clé publique d'Alice que tout le monde peut conslter")
print("n =",na)
print("exposent :",ea)
print("*******************************************************************")
print("il est temps de lui envoyer votre secret ")
print("*******************************************************************")
x=input("appuyer sur entrer")
secret=longueurMaximale(x1b,x2b)
print("*******************************************************************")
print("voici la version en nombre décimal de ",secret," : ")
num_sec=home_string_to_int(secret)
print(num_sec)
print("voici le message chiffré avec la publique d'Alice : ")
chif=home_mod_expnoent(num_sec, ea, na)
print(chif)
print("*******************************************************************")
print("On utilise la fonction de hashage SHA256 pour obtenir le hash du message",secret)
Bhachis0=hashlib.sha256(secret.encode(encoding='UTF-8',errors='strict')).digest() #SHA256 du message
print("voici le hash en nombre décimal ")
Bhachis1=binascii.b2a_uu(Bhachis0)
Bhachis2=Bhachis1.decode() #en string
Bhachis3=home_string_to_int(Bhachis2)
print(Bhachis3)
print("voici la signature avec la clé privée de Bob du hachis")
signe=home_mod_expnoent(Bhachis3, db, nb)
print(signe)
print("*******************************************************************")
print("Bob envoie \n \t 1-le message chiffré avec la clé public d'Alice \n",chif,"\n \t 2-et le hash signé \n",signe)
print("*******************************************************************")
x=input("appuyer sur entrer")
print("*******************************************************************")
print("Alice déchiffre le message chiffré envoyé par Bob  \n",chif,"\nce qui donne ")
dechif=home_int_to_string(home_mod_expnoent(chif, da, na))
print(dechif)
print("*******************************************************************")
print("Alice déchiffre la signature de Bob \n",signe,"\n ce qui donne  en décimal")
designe= home_crt(signe, eb, nb, x1b, x2b)
print(designe)
print("Alice vérifie si elle obtient la même chose avec le hash de ",dechif)
Ahachis0=hashlib.sha256(dechif.encode(encoding='UTF-8',errors='strict')).digest()
Ahachis1=binascii.b2a_uu(Ahachis0)
Ahachis2=Ahachis1.decode()
Ahachis3=home_string_to_int(Ahachis2)
print(Ahachis3)
print("La différence =",Ahachis3-designe)
if (Ahachis3-designe==0):
    print("Alice : Bob m'a envoyé : ",dechif)
else:
    print("FAILED")
