###############   
## sevidor ssh##   
###############   
### el archivo /etc/ssh/sshd_config   
**Habilitar pantallas remotas  redirección X**    
X11Forwarding yes   
X11DisplayOffset 10   
Compression delayed #configuración conveniente   
_en el cliente tambien descomentar los X11_   
   
**aceptar escuchas de peticion**   
ListenAddres 127.0.45.0   
   
**otros :**   
PermitRootLogin [yes/no] --  usuario root se puede conectar al servidor   
RSAAuthentification [yes/no] -- Autenticación RSA activada   
PubkeyAuthentification --  permitida la autenticación por clave publica   
RhostsAuthentification -- Autenticación por rhost , no es seguro   
HostbasedAuthentification -- Autenticación por host y no por usuario   
PasswordAuthentification --  autenticación normal (por contraseña, en caso de fallo de las demas)   
MaxAuthTries (x) -- Numero máximo de reintentos de conexión   
Hostkey [ruta/del/archivo] -- Archivo contiene la clave privada del servidor   
AllowUsers [user1] [user2] -- Lista de usuarios permitidos que tienen permiso para acceder al servidor   
Banner		--  poner mensaje de bienvenida    
   
   
   
###############   
## cliente ssh##   
###############   
### el archivo /etc/ssh/ssh_config   
Protocol --  protocolo a usar (versión SSH)   
PasswordAuthentification --acceso se realizara o no por contraseña   
PubkeyAuthentification -- Autenticación por clave publica   
ForwardX11 -- Ejecución de aplicaciones X11 en el cliente   
**puerto por defecto**   
Port 22   
**escucha en todos los interfaces**   
ListenAddress 0.0.0.0   
**dónde se encuentra la llave del host**   
HostKey /etc/ssh/ssh_host_key   
**dónde se encuentra la simiente aleatoria**   
RandomSeed /etc/ssh/ssh_random_seed   
**durante cuanto tiempo dura la llave del servidor**   
ServerKeyBits 768   
**cuánto tiempo se tiene para introducir las credenciales**   
LoginGraceTime 300   
**cada cuánto tiempo se regeneran las llaves del servidor**   
KeyRegenerationInterval 3600   
**permitir hacer login al root**   
PermitRootLogin no   
**ignorar los ficheros .rhosts de los usuarios**   
IgnoreRhosts yes   
**para asegurarse de que los usuarios no hacen tonterías**   
StrictModes yes   
**Si es sí no hace log de nada. Queremos hacer log de logins/etc.**   
QuietMode no   
**¿reenviar X11? no habría por qué en un servidor**   
X11Forwarding no   
**quizás no querramos hacer demasiado log**   
FascistLogging no   
**mostrar el mensaje del día**   
PrintMotd yes   
**se asegura de que las sesiones se desconectan correctamente**   
KeepAlive yes   
**¿quién está haciendo el logging?**   
SyslogFacility DAEMON   
**la autentificación está usando rhosts o /etc/hosts.equiv**   
RhostsAuthentication no   
**permitir autentificación RSA pura? Es bastante segura**   
RSAAuthentication yes   
**permitir a los usuarios que utilicen su login/contraseña habitual?**   
PasswordAuthentication yes   
**permitir cuentas con contraseñas vacias?**   
PermitEmptyPasswords no   
   
   
   
Otras directivas sshd_conf útiles incluyen:   
AllowGroups — permitir a grupos explícitamente (/etc/group) hacer login utilizando ssh   
DenyGroups — deshabilitar explícitamente hacer login a grupos (/etc/groups)   
DenyUsers — bloquear explícitamente a los usuarios el hacer login   
AllowHosts — permitir ciertos hosts, al resto se les denegará   
DenyHosts — bloquea ciertos hosts, al resto se les permitirá   
IdleTimeout time — tiempo en minutos/horas/días/etc, que fuerza un logout haciendo un SIGHUP del proceso   
   
   
   
#############   
##   SCP   ##   
#############   
### para bajar download desde local a exterior   
**ejemplo: desde host julio ruta a la carpeta local ~/local**   
scp -r usuario@host:ruta-externa  ruta-local   
scp -r  julio@192.168.1.33:'/media/10/jojo/' ~/local   
**para subir upload desde local al exterior**   
$ scp -r viajealsur/ tomas@bootlog.cl:/www/sitio/fotos   
**para subir varios archivos en conjunto**   
$ scp ca.crt client1.crt client1.key invitado@192.168.1.33:~   
   
   
   
   
   
############################   
## LLaves y conexion remota##   
############################   
### claves públicas y privadas   
**se almacenan en:**   

| Ruta | Descripcion |
| --- | --- |
| $HOME/.ssh/id_dsa | para la clave privada |
| $HOME/.ssh/id_dsa.pub | para la clave pública. |

   
### Generar par de llaves   
ssh-keygen -t dsa   	(usado por USA)   
ssh-keygen -t rsa   
>	Enter passphrase  #en caso quiera usarse contraseña para loguearse   
   
*otros tipos de algoritmos que podemos usar*   
rsa, dss, ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521    
dsa es deprecated     
   
ssh-keygen -t rsa -b 2048  [-f nombre_archivo]   
_sino se pone -f entonces se genera en el archivo ~.ssh/id_rsa_   
**mostrar fingerprint -l private-public key (buena)**   
ssh-keygen -l -f id_rsa   
_Donde id_rsa es la priv key_   
**Cambiar password   
ssh-keygen -p -f id_rsa   
**mostrar llave publica desde una llave privada, sin mostrar "comentarios" , debe ser igual a id_rsa.pub, segun el ejemplo**   
ssh-keygen -y -f ~/.ssh/id_rsa   
**Generando par de llaves sin contraseña  -N '' con comentario -C  (recomendado)**   
ssh-keygen -t rsa -b 2048 -f ~/.ssh/dummy-ssh-keygen.pem -N '' -C "Test Key Luis"   
   
**comprobando acceso a un servidor ssh**   
ssh -T -vv git@github.com   
ssh -T -vv git@bitbucket.org   
   
   
### compartiendo clave publica   
$ssh usuario@servidor.dominio.es \   
       'cat >> .ssh/authorized_keys2' < .ssh/id_dsa.pub   
**otra forma:**   
cat ~/.ssh/id_rsa.pub | ssh user@machine “mkdir ~/.ssh; cat >> ~/.ssh/authorized_keys”   
**tambien se puede compartir claves directamente con el comando**   
ssh-copy-id -i /home/mb/.ssh/id_rsa.pub user@ip_del_otro_servidor   
**tambien de forma simplificada (recomendado), puede ser rsa o dsa**   
ssh-copy-id  user@ip_del_otro_servidor   
_Para que funcione  ssh-copy-id el agente tiene que estar activo para la sesión. Si no lo has puesto que lo arranque al inicio, tendrás que arrancarlo desde la consola ejecutando ssh-add._   
   
**otra forma usando agente_ssh , compartir llave publica (no pedir passw)**   
**cliente**_   
eval 'ssh-agent'   
scp /home/mad/.ssh/id_rsa_mad.pub mad@192.168.1.100:/home/mad   
_en archivo /etc/ssh/ssh_config_   
ForwardAgent yes   
_**servidor**_   
**//darle permisos (755 al menos).**   
AuthorizedKeysFile /home/mad/.ssh/authorized_keys   
cat /home/mad/id_rsa_mad.pub >> /home/mad/.ssh/authorized_keys    
   
**Transferir la clave pública SSH a otra máquina en un solo paso:**   
ssh-keygen; ssh-copy-id user@host; ssh user@host   
   
**ssh-add    saltar contraseña, conectarse evitando contraseña(funciona)  **   
_ssh-agent en un programa que almacena las claves privadas y las utiliza en cada sesión ssh que establezcamos en la sesión actual, lo ejecutamos y añadimos la clave id_rsa2:_   
ssh-agent /bin/bash   
ssh-add ~/.ssh/nuestra_llave_privada   
   
   
### Borrar eliminar una linea en el fichero known_hosts   
ssh-keygen -R hostname o <ip>   
**verificar esto**   
ssh-keygen -r fingerprint   
   
### Ignorar el warning de Host cambiado   
ssh -o "StrictHostKeyChecking no" -l user HOST   
o   
ssh -o StrictHostkeyChecking=no -l user HOSTS   
También se puede añadir al .ssh/config, por supuesto.   
   
   
   
   
### conexion a un servidor remoto   
ssh host_remoto   
ssh usuario_remoto@host_remoto   
ssh -l usuario_remoto host_remoto   
   
### conexion modo seguro (funciona)   
ssh -p 1056 -c blowfish -C -l carlos -q -i myself 192.168.1.258   
-p Especifica el puerto para conectarse en el host remoto.   
-c Especifica cómo se va a cifrar la sesión.   
-C Indica que se deberá comprimir la sesión.   
-l Indica el usuario con el que se logueará en el host remoto.   
-q Indica que los mensajes de diagnostico sean suprimidos.   
-i Indica el archivo con el que se identificará (llave privada)    
**otra forma, forzando ipv4, se omiten control de sesiones**    
ssh -4 -C -c blowfish-cbc usuario@host   
**modo seguro    (por probar -m)**   
ssh -p PUERTO -c aes256-ctr -m hmac-sha2-512 -C IP   
con -c se especifica el algoritmo de cifrado empleado, donde los ctr (counter mode) son los mas recomendados (aes256-ctr y aes196-ctr), y si no los cbc (cipher-block chaining): aes256-cbc,aes192-cbc, blowfish-cbc, cast128-cbc   
-m	el algoritmo empleado para hashes,   
   
###	conexion con interfaz grafica -X   
`ssh -X usario@host [programa]`   
[programa] = paquete remoto que queremos ejecutar, ejemplo Gimp   
**otra forma (por probar)**   
ssh -n remotehost -l remoteuser comando   
**otra forma (probar)**   
ssh -fX user@host gimp   
   
   
   
**ejecutar comandos en un host remoto**   
ssh usuario_remoto@host_remoto "find /tmp -name *.txt"   
**correr un comando remoto por ssh**   
ssh -p 2222 username@hostname pwd   
   
   
**script.- buscar en varios host remotos**   

```
#!/usr/bin/perl   
@hosts=(   
    "usuario1\@maquina1.guay.es",   
    "usuario2\@maquina2.guay.es"   
);   
die "Uso: runonall \'command\'\n" unless $ARGV[0];   
foreach(@hosts){   
  print "$_ -> $ARGV[0]:\n";   
  print `ssh $_ $ARGV[0]`;   
```   



   
### llavero publico, podemos almacenar rutas de llaves diferentes al x defecto (id_rsa.pub)   
_sino lo almacenamos aqui, sera imposible a usuarios remotos poder conectarse_   
cat >> ~/.ssh/config << EOF   
Host live.debian.net   
     Hostname live.debian.net   
     User git   
     IdentityFile ~/.ssh/identity.d/git@live.debian.net   
Host miclave.bitbucket.org   
	HostName bitbucket.org   
	PreferredAuthentications publickey   
	IdentityFile /home/usuario/.ssh/miclave   
EOF   
**otra forma, si solo tenemos una llave**   
IdentityFile /home/mb/.ssh/git_remote_repo.pub   
   
   
**bloquear conexion ssh**   
_crear este archivo_   
touch /etc/ssh/sshd_not_to_be_run    
   
   
   
### crear tunel que pase a traves de un tercer pc q esta en medio   
**procedimientos**   
   
1. conexion bloqueada, error   
telnet 172.16.1.2:25   
2. esquema de la ruta tunneling   
10.1.1.10:1234 (maquina local, con puerto local"cualquiera")-> 172.16.1.1 (pc en medio,nuestro pc en casa)->   172.16.1.2:25 (pc al q queremos acceder)   
3. conectandonos   
ssh -L    puerto_local:ip_puerto_objetivo    ip_pc_medio   
ssh -L 1234:172.16.1.2:25 user@172.16.1.1   
4. ingresando a la maquina local que nos redigira automaticamente a 172.16.1.2:25   
telnet 10.1.1.10 1234   
**o tambien (probar)**   
telnet localhost   
   
**otra forma Conexión SSH por medio de “host in the middle”:**   
ssh -t host_alcanzable ssh host_inalcanzable   
   
   
**conexion con tunel a host remoto al puerto 80 servidor web**   
ssh -N -L2001:localhost:80 <user@host>   
**ahora podemos conectarnos desde la maquina local por el tunel   
  http://localhost:2001/   
   
   
   
   
   
   
#####################################   
##  sshfs  Montar Carpeta Remota   ##   
#####################################   
**comprobar si el usuario esta dentro del grupo fuse**   
ej: groups knoppix   
**Paquetes requeridos para Debian.**   
apt-get update && apt-get install fuse-utils sshfs;   
**usuario debe pertencer al grupo fuse**   
sudo usermod -G fuse -a usuario_local   
**o tambien puede funcionar**   
adduser usuario fuse   
**reiniciando el sistema para actualizar el modulo de kernel,y cargando en memoria**   
sudo modprobe fuse   
**montar carpeta remota en maquina local para editar comodamente con gui local**   
sshfs  knoppix@192.168.56.101:/home/knoppix/monkey ~/compartido   
**desmontando el directorio compartido**   
fusermount -u ~/compartido/   
   
**fstab para arranque automatico (probar no funciona montando carpetas --sin acceso)**   
sshfs#knoppix@192.168.56.101:/home/knoppix/monkey /home/mb/compartido  fuse defaults,auto 0 0   
**esta linea funciona  (recomendado)**   
sshfs#knoppix@192.168.56.5:/home/knoppix/monkey /home/mb/compartido  fuse noauto,rw,user 0 0   
**esta linea tambien funciona (recomendado)**   
sshfs#ubu-server@192.168.56.3:/home/ubu-server/joder /home/mb/compartido  fuse  user,noauto,transform_symlinks  0 0   
_consideraciones:_   
-usar claves publicas    
-en gnome se debe montar la carpeta desde "lugares" ->   
-sino se puede montar entrar desde la consola con    
	sudo nautilus carpeta   
** mayor referencia en **   
/etc/fuse.conf   
   
**agregar el modulo fuse para no cargarlo cada vez**   
sudo sh -c "echo fuse >> /etc/modules"   
   
**sshfs tiene varios parámetros opcionales, los cuales lo hacen bastante nice :)**   
-o reconnect   
reconnect to server   
-o sshfs_sync   
synchronous writes   
-o no_readahead   
synchronous reads (no speculative readahead)   
-o sshfs_debug   
print some debugging information   
-o cache=YESNO   
enable caching {yes,no} (default: yes)   
-o cache_timeout=N   
sets timeout for caches in seconds (default: 20)   
-o cache_X_timeout=N   
sets timeout for {stat,dir,link} cache   
   
_hacer script lanzado desde .xsession, el cual se encarga de montar un directorio de musica desde otra pc_   
   
   
   
   
   
##########################   
##	MISCELANEA	##   
##########################   
**Enviar el sonido del micrófono local a los altavoces de un host remoto:**   
dd if=/dev/dsp | ssh -c arcfour -C user@host dd of=/dev/dsp   
   
**Comparar un archivo remoto con uno local:**   
ssh user@host cat /ruta/del/archive_remoto | diff /ruta/del/archive_local   
   
**Copiar desde host1 a host2 desde tu host:**   
ssh root@host1 "cd /directorio/a/copiar/ && tar --cf -." | ssh root@host2 "cd /directorio/destino/de/copia/ && tar --xf --"   
   
**copiar una base de datos con directorios y archivos a otro servidor ldap**   
tar cvfp - /var/lib/ldap | ssh root@ESCLAVO "cd / && tar xvfp -"   
   
**Crear una conexión persistente a una máquina:**   
ssh -MNf user@host   
_de esta forma ya no se crearan nuevos sockets_   
**en el archivo ~/.ssh/config:   
>	Host host   
>	ControlPath ~/.ssh/master-%r@%h:%p   
>	ControlMaster no   
   
**Adjuntar la pantalla por SSH:**   
ssh -t remote_host screen -r   
   
   
**Test de rendimiento del canal SSH en tiempo real:**   
yes | pv | ssh $host "cat > /dev/null"   
_*debes instalar pv**_   
http://www.ivarch.com/programs/pv.shtml   
   
**conectarse usando  screen**   
ssh -t user@some.domain.com /usr/bin/screen -xRR   
   
**trabajando con rsync, reanudando copia en caso falle**   
rsync --partial --progress --rsh=ssh $file_source $user@$host:$destination_file   
rsync --partial --progress --rsh=ssh $file_source $user@$host:$destination_file local -> remote   
rsync --partial --progress --rsh=ssh $user@$host:$remote_file $destination_file remote -> local   
   
   
**Analizar tráfico de forma remota por SSH con Wireshark:**   
ssh root@server.com 'tshark -f "port !22" -w -' | wireshark -k -i -   
**otra forma usando tcpdum en lugar de tshark**   
ssh root@example.com tcpdump -w -- 'port !22' | wireshark -k -i -   
   
**Mantener abierta una sesión SSH para siempre**   
**util para conexion wifi   
autossh -M50000 -t server.example.com 'screen -raAd mysession'   
   
**Acelerador de ancho de banda con cstream:**   
tar -cj /backup | cstream -t 777k | ssh host ‘tar -xj -C /backup’   
_comprime en bzip una carpeta y la transmite al host por la red a 777Kbit/s_   
**otro truco cstream**   
echo w00t, i’m 733+ | cstream -b1 -t2   
   
   
   
**Copiar la entrada estándar stdin al buffer X11 local**   
ssh user@host cat /path/file_remote | xclip   
   
**copiar una base de datos MySQL a un nuevo servidor vía SSH con un comando:**   
mysqldump --add-drop-table --extended-insert --force --log-error=error.log -uUSER -pPASS OLD_DB_NAME | ssh -C user@newhost "mysql -uUSER -pPASS NEW_DB_NAME"   
   
**Ejecutar comandos de consola remotos por SSH sin comillas de escape:**   
ssh host -l user $(<cmd.txt)   
**Método mas simple y mas portable:**   
ssh host -l user “`cat cmd.txt`”   
   
**Llamar a puertos (port knocking):**   
knock [host] 3000 4000 5000 && ssh -p [port] user@host && knock [host] 5000 4000 3000   
_Llama a los puertos 3000 4000 5000 para abrir el puerto de un servicio (ssh por ejemplo) y vuelve a llamar a los puertos 5000 4000 3000 para cerrar el acceso al dicho servicio. Para esto es necesario tener instalado knockd._   
_Un ejemplo de configuración del servicio knockd mediante el archivo knockd.conf para que interpretase las llamadas anteriores sería:_   
[options]   
Logfile = /var/log/knockd.log   
[openSSH]   
sequence = 3000,4000,5000   
command = /sbin/iptables -A input -i eth0 -s %IP% -p tcp -dport 22 -j accept   
tcpflags = syn   
[closeSSH]   
sequence = 5000,4000,3000   
seq_timeout = 5   
command = /sbin/iptables -D input -i eth0 -s %IP% -p tcp -dport 22 -j accept   
tcpflags = syn   
   
   
###   hacer copias de seguridad con dd   
**backup desde la máquina local a la máquina remota**   
find . --print | cpio -ocvB | ssh miguel dd of=/dev/ftape   
ssh miguel dd if=/dev/ftape | cpio -itvcB   
**haciendo backup a copia remota**   
ssh gnome2 ‘find . --print | cpio -ocvB’ | dd of=/dev/ftape   
dd if=/dev/ftape | ssh gnome2 cpio -itvcB    
   
   
   
### patear “idle users” en cónsolas bash, despues de estar inactivos 15 minutos   
** Agregar a profile.d**   
cat <<EOF > /etc/profile.d/os-security.sh   
** timeout de 900 sec (5 min) para shell bash**   
readonly TMOUT=900   
export TMOUT   
EOF   
**hacer el script ejecutable:**   
chmod +x /etc/profile.d/os-security.sh   
   
   
   
#############################   
## conversiones encriptacion##   
#############################   
###  Openssl, llaves publicas   
**con openssl extraer la llave publica**   
openssl rsa  -pubout 	     -in net-mon.key -out net-mon.key.pub   
**convirtiendo llave publica en format ssh **   
ssh-keygen -i -m PKCS8 -f net-mon.key.pub.key > net-mon.key.pub.key.ssh   
**comprobar que tuvimos exito en la conversion**   
ssh-keygen -l -y -f net-mon.key.pub.key.ssh   
   
**la llave privada generado x openssh puede ser leida x openssh directamente sin conversion**   
**creando llave privada/publica ssh**   
ssh-keygen -f test-user   
**creando certificado X509 directamente desde una llave privada ssh**   
openssl req -x509 -days 365 -new -key test-user -out test-user-cert.pem   
   
**las llaves privadas pueden ser leidas directamente desde ssh**   
antes de leerlos con ssh deben tener permiso 600   
   
### OpenSSH to GnuPG S/MIME   
**First we need to create a certificate (self-signed) for our ssh key:**   
openssl req -new -x509 -key ~/.ssh/id_rsa -out ssh-cert.pem   
**We can now import it in GnuPG**   
openssl pkcs12 -export -in ssh-certs.pem -inkey ~/.ssh/id_rsa -out ssh-key.p12   
gpgsm --import ssh-key.p12   
_Notice you cannot import/export DSA ssh keys to/from GnuPG_   
   
   
   
   
   
   
##################   
##	SFTP	##   
##################   
### primera forma   
**en archivo /etc/ssh/sshd_config    
Subsystem sftp internal-sftp   
UsePAM yes   
Match User  luis   
	ChrootDirectory /luis   
	ForceCommand  internal-sftp   
   
### segunda forma (recomendado para vhost)   
**si se quiere usar grupo de usuarios**   
Subsystem sftp internal-sftp   
Match Group sftpusers   
	ChrootDirectory %h #la direccion del home, cambiar a chown user:root, o chown user:Domain Users, sino saldra error   
	ForceCommand internal-sftp   
	AllowTcpForwarding no   
**Utilice el mandato groupadd para crear el grupo sftpusers.**   
groupadd sftpusers   
**Añada a los usuarios a los cuales se quiera enjaular, al grupo sftpusers**   
gpasswd -a perengano sftpusers   
_de esta forma, solo los usuarios pertenecientes al grupo sftpusers podran usar sftp, pero no scp ni ssh_   
   
**agregando permisos al directorio comprometido**   
chown root:root /home/perengano   
chmod 755 /home/perengano   
   
usermod -s /sbin/nologin perengano   
   
sftp perengano@192.168.80.8   
   
_ funciona dentro de la raiz / own = root , pero en otra ubicacion, deniega, usar setfacl para permitir permisos _   
   
   
## ver que las configuraciones no contengan errores   
sshd -t   
**ver la configuracion del archivo**   
sshd -T   
   
### errores   
unable to write 'random state'   
borrar ~/.rnd   
   
   
   
   
### ingresar rapidamente por ssh sin usar muchos parametros en la shell,    
### ya estan expresados en ~/.ssh/config   
@@un ejemplo   
Host somealias   
    HostName example.com   
    Port 2222   
    User someuser   
    IdentityFile  ~/.ssh/id_example   
    IdentitiesOnly yes   
   
Host anotheralias   
    HostName 192.168.33.10   
    User anotheruser   
    PubkeyAuthentication no   
   
How aws   
    HostName some.address.ec2.aws.com   
    User awsuser   
    IdentityFile  ~/.ssh/aws_identity.pem   
    IdentitiesOnly yes   
   
@@otro ejemplo   
**### default for all ##**   
Host *   
     ForwardAgent no   
     ForwardX11 no   
     ForwardX11Trusted yes   
     User nixcraft   
     Port 22   
     Protocol 2   
     ServerAliveInterval 60   
     ServerAliveCountMax 30   
    
**## override as per host ##**   
Host server1   
     HostName server1.cyberciti.biz   
     User nixcraft   
     Port 4242   
     IdentityFile /nfs/shared/users/nixcraft/keys/server1/id_rsa   
    
**## Home nas server ##**   
Host nas01   
     HostName 192.168.1.100   
     User root   
     IdentityFile ~/.ssh/nas01.key   
    
**## Login AWS Cloud ##**   
Host aws.apache   
     HostName 1.2.3.4   
     User wwwdata   
     IdentityFile ~/.ssh/aws.apache.key   
    
**## Login to internal lan server at 192.168.0.251 via our public uk office ssh based gateway using ##**   
**## $ ssh uk.gw.lan ##**   
Host uk.gw.lan uk.lan   
     HostName 192.168.0.251   
     User nixcraft   
     ProxyCommand  ssh nixcraft@gateway.uk.cyberciti.biz nc %h %p 2> /dev/null   
    
**## Our Us Proxy Server ##**   
**## Forward all local port 3128 traffic to port 3128 on the remote vps1.cyberciti.biz server ##**   
**## $ ssh -f -N  proxyus ##**   
Host proxyus   
    HostName vps1.cyberciti.biz   
    User breakfree   
    IdentityFile ~/.ssh/vps1.cyberciti.biz.key   
    LocalForward 3128 127.0.0.1:3128   
   
@@otro ejemplo   
Host *   
    PreferredAuthentications publickey, keyboard-interactive   
    SeverAliveInterval 120   
    ServerAliveCountMax 30   
   
**explicacion**   
Host : Defines for which host or hosts the configuration section applies. The section ends with a new Host section or the end of the file. A single * as a pattern can be used to provide global defaults for all hosts.   
HostName : Specifies the real host name to log into. Numeric IP addresses are also permitted.   
User : Defines the username for the SSH connection.   
IdentityFile : Specifies a file from which the user’s DSA, ECDSA or DSA authentication identity is read. The default is ~/.ssh/identity for protocol version 1, and ~/.ssh/id_dsa, ~/.ssh/id_ecdsa and ~/.ssh/id_rsa for protocol version 2.   
ProxyCommand : Specifies the command to use to connect to the server. The command string extends to the end of the line, and is executed with the user’s shell. In the command string, any occurrence of %h will be substituted by the host name to connect, %p by the port, and %r by the remote user name. The command can be basically anything, and should read from its standard input and write to its standard output. This directive is useful in conjunction with nc(1) and its proxy support. For example, the following directive would connect via an HTTP proxy at 192.1.0.253:   
ProxyCommand /usr/bin/nc -X connect -x 192.1.0.253:3128 %h %p   
LocalForward : Specifies that a TCP port on the local machine be forwarded over the secure channel to the specified host and port from the remote machine. The first argument must be [bind_address:]port and the second argument must be host:hostport.   
Port : Specifies the port number to connect on the remote host.   
Protocol : Specifies the protocol versions ssh(1) should support in order of preference. The possible values are 1 and 2.   
ServerAliveInterval : Sets a timeout interval in seconds after which if no data has been received from the server, ssh(1) will send a message through the encrypted channel to request a response from the server. See blogpost “Open SSH Server connection drops out after few or N minutes of inactivity” for more information.   
ServerAliveCountMax : Sets the number of server alive messages which may be sent without ssh(1) receiving any messages back from the server. If this threshold is reached while server alive messages are being sent, ssh will disconnect from the server, terminating the session.   
   
**solamente tipeariamos para ingresar por ssh**   
ssh nas01   
**tambien podriamos crear un alias**   
alias server1="ssh -i /nfs/shared/users/nixcraft/keys/server1/id_rsa -p 4242 nixcraft@server1.cyberciti.biz"   
Then, to ssh into the server1, instead of typing full ssh -i /nfs/shared/users/nixcraft/keys/server1/id_rsa -p 4242 nixcraft@server1.cyberciti.biz command, you would only have to type the command ‘server1’ and press the [ENTER] key:   
$ server1   
   
   
   
###############   
##  Ansible  ##   
###############   
**conexion ssh para realizar tareas a multiples host que le indiquemos**   
sudo apt-add-repository -y ppa:rquillo/ansible   
sudo apt-get update   
sudo apt-get install -y ansible   
**Then, configure one or more servers in the /etc/ansible/hosts directory:**   
[web]   
192.168.22.10   
192.168.22.11   
192.168.22.12   
**Save that file and then let's run a command on all three servers!**   
ansible -k all -m ping -u vagrant   
**This will run "ping" on each server. You'll get some JSON output saying if they were successful or not.**   
**The flags of that command:**   
-k - Ask for password   
all - All servers configured in /etc/ansible/hosts   
-m ping - Use the ping module   
-u vagrant - Login with user "vagrant", which will work if the hosts defined are other vagrant servers. Change the username as needed.   
**You can actually run any command using the "shell" module:**   
ansible -k all -m shell -u vagrant -a "apt-get install nginx"   
**Here, the -a "apt-get install nginx will run the given command using the "shell" module.**   
**Here's more information on running ad-hoc commands with Ansible!**   
