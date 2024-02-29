# Verboten
WU de Verboten 

### Catégorie : 
Forensics

### Flag (officialy) : 
```bi0sctf{w3ll_th4t_w4s_4_v3ry_34sy_chall_b9s0w7}```

### Auteur du challenge : 
gh0stkn1ght

### Desc : 
Randon, an IT employee finds a USB on his desk after recess. Unable to contain his curiosity he decides to plug it in. Suddenly the computer goes haywire and before he knows it, some windows pops open and closes on its own. With no clue of what just happened, he tries seeking help from a colleague. Even after Richard's effort to remove the malware, Randon noticed that the malware persisted after his system restarted.

# Write-Up : 

Sur ce challenge ma foi particulier dans sa conception (j'y reviendrai à la fin du write-up), nous avons 9 questions précises à rentrer sur une instance afin d'obtenir le flag.

### Identification : 
Une fois avoir téléchargé le fichier zip de 120 MO environ (plutôt léger pour une image), On fait face à une image ad1 (d'ou le fait qu'elle soit si légère).
#### AD1 kessecé ?
Une image AD1 ou ``AccessData Logical Images`` est tout simplement un fichier "image" qui va répertorier/récupérer tout les fichiers disponibles sur un disque ou une partition puis en créer une sorte d'archive/container.

En l'ouvrant on y voit donc une image Windows.

## Questions : 
Bien ! C'est là que tout commence, par ma stupidité légendaire (et du au fait que l'instance ne marchait pas) j'ai essayé de trouver un flag de par le malware 🤦‍♂️ à tel point que j'ai fini par me connecter en FTP sur un vrai Agent Tesla Actif
et y trouver des logs de vraies personnes : 

![image](https://github.com/xTommyBoy/verboten/assets/66128183/f53e5b4c-3a87-40e6-a3c8-75c05a5a5118)

#### Question 1 : 

``What is the serial number of the sandisk usb that he plugged into the system? And when did he plug it into the system?``

Durant l'année 2024 j'ai fait la merveilleuse découverte d'un excellent parser (avec ces défauts bien-sûr) du nom d'ArtiFast : https://forensafe.com/artifast.html
Ce tool parse presque tout de disponible sur une image windows avec une certaine précision cependant il sert uniquement de parser via des dossiers de fichiers impossible de lui faire monter une image ou quoi que ce soit d'autre qu'un dossier.

Bref, après analyse magie ! le tool nous donne tout ce qui est demandé : 

![image](https://github.com/xTommyBoy/verboten/assets/66128183/848cdd86-9602-4934-a0b4-1044bee68ab8)

Le flag ne passait pas au début car pour aucune raison c'etait le parentID qui était attendu et non le serial number de la clé en elle même 🤷

Manuellement l'information était récupérable dans le registre ``SYSTEM`` en le montant ou en le déchiffrant avec un logiciel fait pour en utilisant Autopsy par exemple : 

![image](https://github.com/xTommyBoy/verboten/assets/66128183/273ff4be-8443-48ca-866c-38e4f74d6b3c)

Dans ``ControlSet01\Enum\USB`` on peut y apercevoir l'id de la clé usb ainsi que dans ``ControlSet01\Enum\USBSTOR`` le parentID.

Le flag est donc : ``verboten{4C530001090312109353&0:2024-02-16-12-01-57}``

#### Question 2 :

``What is the hash of the url from which the executable in the usb downloaded the malware from? Format: verboten{md5(url)}``

En regardant dans les dossiers (dans ``Users\randon\AppData\Local\Chome\User Data\Default``) on peut y apercevoir un dossier google chrome avec un profil, ce profil n'étant pas vide je décide d'extraire tout ça j'extrait donc le fichier History et je le regarde via DB Browser : 

![image](https://github.com/xTommyBoy/verboten/assets/66128183/04700c36-a59d-44c5-8a53-c48a303a4d17)

En regardant dans la field des url chains (historique des urls ou des téléchargements ont été effectués), On peut apercevoir l'url du malware.

Le flag est donc : ``verboten{11ecc1766b893aa2835f5e185147d1d2}``

#### Question 3 : 

``What is the hash of the malware that the executable in the usb downloaded which persisted even after the efforts to remove the malware? Format: verboten{md5{malware_executable)}``

Pour cette question là rien de bien compliqué, Agent Tesla utilise les dossiers de persistence et de startup de base qu'un RAT classique peut faire, en regardant dans les dossiers on fini par tomber sur le malware dans le dossier startup : 

![image](https://github.com/xTommyBoy/verboten/assets/66128183/869921d0-e736-465a-8c2a-3ae92c5c17d5)

Le flag est donc : ``verboten{169cbd05b7095f4dc9530f35a6980a79}``

#### Question 4 :

``What is the hash of the zip file and the invite address of the remote desktop that was sent through slack? Format: verboten{md5(zip_file):invite_address}``

C'est à partir de cette question que j'ai commencé à apprendre des choses, en pensant que Slack était relativement "anonyme friendly" les caches étaient pour moi chiffrées ou cachées mais que néni ! les artifacts sont quasiment les mêmes que ceux de google chrome (pour préciser un artifact peut être traduit comme une trace/un log en DFIR)

En allant donc dans le dossier ``Cache`` de Slack : ``Users/randon/AppData/Roaming/Slack/Cache/Cache_Data`` on peut voir que l'arborescence est très très similaire à Chrome : https://medium.com/@jsaxena017/web-browser-forensics-part-1-chromium-browser-family-99b807083c25

Je décide donc de lancer ChromeCacheViewer: https://www.nirsoft.net/utils/chrome_cache_view.html

Et bingo ! le logiciel m'affiche bien tout les caches présents dans Slack, un petit coup de ctrl + f pour chercher comme dit dans l'énnoncé un zip :

![image](https://github.com/xTommyBoy/verboten/assets/66128183/6425404c-e6c9-4769-acfd-ebbc71599b78)

C'est tout bon ! on télécharge l'artifact, on transforme le fichier zip en md5 (dédicasse à nils qui m'a fait repenser à l'existence de la commande md5sum), pour l'invite adress j'ai essayé un parser qui marchait pas bien https://github.com/0xHasanM/Slack-Parser j'ai donc récupéré le fichier IndexedDB et j'ai parsé avec ma madeleine de proust : https://github.com/horsicq/Detect-It-Easy en filtrant correctement on trouve donc l'adresse, il ne nous reste plus qu'a flag !

![image](https://github.com/xTommyBoy/verboten/assets/66128183/b26b0937-4a03-4ab7-ae1a-beec7c8ba26a)

Le flag est donc : ``verboten{b092eb225b07e17ba8a70b755ba97050:1541069606}``

#### Question 5 : 

``What is the hash of all the files that were synced to Google Drive before it was shredded?
Format: verboten{md5 of each file separated by ':'}``

En naviguant dans les dossiers de l'utilisateur j'ai fini par trouver un dossier se nommant ``DriveFS`` dans : ``Users/randon/AppData/Local/Google/DriveFS/110922692857671422467/content_cache/`` (le dossier cache de google drive en gros)
on peux donc y trouver 5 fichiers avec une suite de chiffre et mise dans l'ordre : 
![image](https://github.com/xTommyBoy/verboten/assets/66128183/051386e3-5bb3-40cc-9361-1db108be0c9e)

en récupérant leurs hashs md5 un a un on peut construire le flag 

Le flag est donc : ``verboten{ae679ca994f131ea139d42b507ecf457:4a47ee64b8d91be37a279aa370753ec9:870643eec523b3f33f6f4b4758b3d14c:c143b7a7b67d488c9f9945d98c934ac6:e6e6a0a39a4b298c2034fde4b3df302a}`` (oui il est extrêmement long)

#### Question 6 :

``What is time of the incoming connection on AnyDesk? And what is the ID of user from which the connection is requested? Format: verboten{YYYY-MM-DD-HH-MM-SS:user_id}``

Encore une fois notre super ami ArtiFast va nous servir, En effet il possede un parser de logiciels précis on coche la bonne case et on recherche : 

![image](https://github.com/xTommyBoy/verboten/assets/66128183/0845d05a-ee87-4069-8273-d2c5820dcef9)

Mais le flag ne passe pas ? Regardons dans le fichier ``ad_svc.trace`` de AnyDesk situé dans ``\ProgramData\AnyDesk`` en l'ouvrant et en regardant attentivement on peut y voir à ``20:29:04`` une connection établie

![image](https://github.com/xTommyBoy/verboten/assets/66128183/32bef213-1b18-4926-80d6-f69c77dcba83)

En utilisant donc ce que ArtiFast à parse et ce qu'on à pu récupérer manuellement via ad.trace on peut donc flag la question ! 

Le flag est donc : ``verboten{2024-02-16-20-29-04:221436813}``

#### Question 7 :

``When was the shredder executed? Format: verboten{YYYY-MM-DD-HH-MM-SS}``

Pour celle ci, j'ai sacrément galéré du au fait que le flag devait être en format 12h ?? et qu'on ne savait pas trop quel timestamp utiliser. En cherchant et en filtrant dans les recherches d'ArtiFast j'ai recherché shredders et de fil en aiguille j'ai fini par tomber sur un fichier Prefetch (un fichier de log permettant de memoriser la configuration d'un Executable pour Windows) executant un fichier disponible dans le dossier shredders nommé "Blank And Secure"

![image](https://github.com/xTommyBoy/verboten/assets/66128183/5fcdae40-e7c0-4de4-8a2d-ad4cf82d4b13)

En y mettant donc la bonne heure donc en UTC +0 et au format 12h on obtiens donc le flag...

verboten{2024-02-16-08-31-06}

#### Question 8 :

``What are the answers of the backup questions for resetting the windows password?Format: verboten{answer_1:answer_2:answer_3}``

Relativement simple, plus que ce que je ne pensais en tout cas un grand merci à Nirsoft encore une fois il à juste fallu récupérer le dossier config et le donner au logiciel de Nirsoft nommé SecurityQuestionsView : https://www.nirsoft.net/utils/security_questions_view.html

Et GGWP !

Le flag est donc : ``verboten{Stuart:FutureKidsSchool:Howard}``

#### Question 9 :

``What is the single use code that he copied into the clipboard and when did he copy it?
Format: verboten{single_use_code:YYYY-MM-DD-HH-MM-SS}``

Et voici la dernière question qui évidemment etait une énorme purge à solve (dédicasse à Lumy pour celle la xD) (encore une fois à cause d'une question de timestamp)

Pour récupérer ce que l'utilisateur avait copié c'était relativement facile en faisant un peu de recherche on peux y trouver un article d'un développeur parlant qu'avec l'activities cache de Windows (appelé par Artifast Windows Timeline, ce fichier lui sert de logger pour windows savoir ce qu'on à executé cliqué etc...) on peux récupérer les données du clipboard il à même fait un logiciel permettant de faire ça : https://github.com/kacos2000/WindowsTimeline/releases/download/v.2.0.3.0/Clippy.exe

Mais (eh oui toujours ce fameux mais...) il récupère tout sauf le timestamp 😭 j'ai donc tenté énormément de choses : du ligne par ligne sur la timeline de ArtiFast en filtrant clipboard en utc +0 et en utc +5.30 (merci au créateur de ne pas du tout m'avoir éclairé sur ça d'ailleurs), utiliser le logiciel windowstimeline de kacos2000 : https://github.com/kacos2000/WindowsTimeline, chercher via notepad++, via DB Browser (j'y reviendrai après) mais rien. En regardant précisemment dans les dossiers de WindowsTimeline sur le github de kacos2000 on peut y voir un "Clipboard.ps1" : https://github.com/kacos2000/WindowsTimeline/blob/master/Clipboard.ps1 assez chiant à mettre en place mais bref, une fois ceci fait on peux y voir 11 entrées :

![image](https://github.com/xTommyBoy/verboten/assets/66128183/16ce903e-5050-44e9-84da-e95c57d6fa26)

et là je vais être honnête : j'ai juste tenté les 11 entrées ! UTC+0 et UTC+5.30 et bingo ? la troisième entrée du notepad était la bonne réponse ce qui nous permet donc d'obtenir notre flag ! 

``bi0sctf{w3ll_th4t_w4s_4_v3ry_34sy_chall_b9s0w7}``

Bon pour revenir à DB Browser normalement j'aurais pu avoir le flag beaucoup plus facilement mais pour une raison obscure le hash de mon ActivitiesCache.db était corrompu ce qui faisait que les ClipboardPayloads n'affichait rien 😭

# Conclusion :

Un challenge très sympa et instructif sur le papier cependant le système de questions était extrêmement mal foutu comme j'ai dit au début il fallait utilisé un math solveur attendre que le script solve l'équation copier la réponse, la donner au serveur puis, acceder au questions et évidemment si il y'avait la moindre faute de frappe ou de copie il fallait tout recommencer depuis le début ! (de la question 1 à 9 bien entendu hein) 

https://cdn.discordapp.com/attachments/1075497745617530931/1212568164081336320/verboten.py?ex=65f24f1a&is=65dfda1a&hm=ff904ee31a666c69cd9e39cdc6a4f8008ceb9e2f30968b679c1ce9d924b72a12& 
voici un solveur pour l'instance mais la question c'est pourquoi ? pourquoi faire une instance pour répondre à des questions sachant qu'il y'a des milliards de façons de mettre des flags dans un système windows ?
autre chose, LES TIMESTAMPS ?? des fois c'etait en UTC 5.30 des fois UTC 0 c'était à en devenir fou. J'ai du créer au moins 5 tickets à cause de ça, puis je veux dire dans certains scenarios oui l'heure peut être importante mais la ça servait juste à rien je pense que les timestamps était juste pour faire plus dur c'est tout. Dommage.

Enfin bref merci d'avoir lu :)
