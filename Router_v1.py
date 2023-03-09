import paramiko
import telnetlib
from getpass import getpass
import time
import socket
import re

#funcion para conectar al router y lanzar comando export por ssh
def accesoRouter(ip, user, pw):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username = user, password = pw, timeout=3)
        
        stdin, stdout, stderr = ssh.exec_command('ip firewall address-list export')
        time.sleep(1)
        rsc_content = stdout.read().decode()
        
        ssh.close()
            
    except paramiko.ssh_exception.AuthenticationException as e:
        print('Autenticacion fallida')
    except socket.timeout as e:
        print("Error de Timeout: No se pudo establecer una conexión con el router en el tiempo especificado.")
    except socket.error as e:
        print("Error de conexión: No se pudo establecer una conexión con el router. Verifique la dirección IP.")
    except Exception as e:
        print(f"Error desconocido: {e}")
        
    return rsc_content

#funcion para guardar el .rsc en un archivo .txt
def guardarArchivo(rsc_content, leerIp):
    with open(leerIp, 'w') as f:
        f.write(rsc_content)

#funcion para lanzar comando disable a la address-list
def disableIps(ip, user, pw):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username = user, password = pw, timeout=5)
        
        stdin, stdout, stderr = ssh.exec_command('ip firewall address-list disable [find list="BLOCKED_USERS"]')
        time.sleep(1)
        salida = stdout.read().decode()
        error = stderr.read().decode()
        
        ssh.close()
        
        if stderr.channel.recv_exit_status() != 0:
            print("Ocurrió un error al ejecutar el comando:", error)
        else:
            print("Comando ejecutado con éxito: \n", salida)
        
    except paramiko.ssh_exception.AuthenticationException as e:
        print('Autenticacion fallida')
    except socket.timeout as e:
        print("Error de Timeout: No se pudo establecer una conexión con el router en el tiempo especificado.")
    except socket.error as e:
        print("Error de conexión: No se pudo establecer una conexión con el router. Verifique la dirección IP.")
    except Exception as e:
        print(f"Error desconocido: {e}")
        
#***** Buscar las ips del firewall segun el rango establecido ***** ### ¡¡¡Uso de expresiones regulares!!!! ###
def encontrarIps(localidad):
    # Abrir el archivo en modo lectura
    with open(localidad, "r") as file:
        # Leer el contenido del archivo
        content = file.read()

        # Buscar todas las direcciones IP en el archivo
        ip_addresses = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)

        # Crear una lista para almacenar las direcciones IP que coincidan con el rango especificado
        filtered_ips = []

        # Iterar sobre todas las direcciones IP encontradas
        for ip in ip_addresses:
            # Dividir la dirección IP en sus cuatro partes
            parts = ip.split(".")

            # Parametros de busqueda (establece un rango para las ips)
            if int(parts[0]) == 10 and int(parts[1]) == 10 and int(parts[2]) >= 32 and int(parts[2]) <= 39 and int(parts[3]) >= 1 and int (parts[3]) <=254:
                # Agregar la dirección IP a la lista de direcciones filtradas
                filtered_ips.append(ip)

    # Imprimir la lista de direcciones IP filtradas
    print(f"Se encontraron {len(filtered_ips)} direcciones IP en el rango especificado: {filtered_ips}")
    return filtered_ips

#Conexion a telnet y apagado de tv
def conTelnet (user, password, guser, gpassword, Host):
    indice = 0
    longitud = len(Host)
    fibrastor = 'Device Model  :   RO 015FT'
    onuDescartada = 'Login incorrect'
    gpon = ""

    while indice < longitud:
        if indice < longitud:
            ip = Host[indice]
            try:
                conexion = telnetlib.Telnet(ip)
                try:
                    equipo = str(conexion.read_until(b"Device Model  :   RO 015FT", timeout=2))
                    if fibrastor in equipo:
                        conexion.read_until(b"login: ", timeout=2)
                        conexion.write(user.encode('ascii') + b'\n')
                        time.sleep(2)
                        if password:
                            conexion.read_until(b"Password: ", timeout=2)
                            conexion.write(password.encode('ascii') + b"\n")
                            time.sleep(2)
                        equipo2 = str(conexion.read_until(b"Login incorrect", timeout=2))
                        conexion.write(b"flash set CATV_ENABLED 0\n")
                        conexion.write(b"exit\n")
                        print(conexion.read_all().decode('ascii'))
                        print(f'Se ejecuto correctamente el comando a la ip {ip}, son {longitud} ips y va en la {indice}')
                        print(f'***************Equipo # {indice}***************')
                    else:
                        print(f'La ip {ip}, no es un equipo Fibrastore\n')
                        
                        
                        

                    equipo = str(conexion.read_until(b"", timeout=2))
                    if gpon in equipo:
                        conexion.read_until(b"login: ", timeout=2)
                        conexion.write(guser.encode('ascii') + b'\n')
                        time.sleep(2)
                        if password:
                            conexion.read_until(b"Password: ", timeout=2)
                            conexion.write(gpassword.encode('ascii') + b"\n")
                            time.sleep(2)
                        conexion.write(b"flash set OLT_CATV_ENABLE 2\n")
                        conexion.write(b"flash set WEB_CATV_ENABLE 2\n")
                        conexion.write(b"flash set GLOBAL_CATV_ENABLE 1\n")
                        time.sleep(1)
                        conexion.write(b"reboot\n")
                        print(conexion.read_all().decode('ascii'))
                        print(f'Se ejecuto correctamente el comando a la ip {ip}, son {longitud} ips y va en la {indice}')
                        print(f'***************Equipo # {indice}***************')
                except EOFError as e:
                    print("Error: la conexión Telnet ha sido cerrada por el host remoto:", e)
                finally:
                    conexion.close()
                
            except socket.timeout as e:
                print(f'Error de Timeout: Verifique su conexión a Internet y que la ip {ip} sea válida, son {longitud} ips y va en la {indice}')
                print(f'***************Equipo # {indice}***************')
            except socket.error as e:
                print('Error de Conexion:', e)
                conexion = telnetlib.Telnet(ip)
                try:
                    conexion.read_until(b"login: ", timeout=2)
                    conexion.write(user.encode('ascii') + b'\n')
                    time.sleep(2)
                    if password:
                        conexion.read_until(b"Password: ", timeout=2)
                        conexion.write(password.encode('ascii') + b"\n")
                        time.sleep(2)
                    equipo2 = str(conexion.read_until(b"Login incorrect", timeout=2))
                    if onuDescartada not in equipo2:
                        conexion.write(b"flash set CATV_ENABLED 0\n")
                        conexion.write(b"exit\n")
                        print(conexion.read_all().decode('ascii'))
                        print(f'Se ejecuto correctamente el comando a la ip {ip}, son {longitud} ips y va en la {indice}')
                        print(f'***************Equipo # {indice}***************')
                        conexion.close()
                except socket.error as e:
                    print('error: ', e)
        
        else:
            print('ocurrio un error de programacion')
        indice += 1
    print(f'\nFinalizó el apagado de tv en esta localidad fueron en total {indice} ips')


#funcion enable al router
def enableIps(ip, user, pw):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username = user, password = pw, timeout=5)
        
        stdin, stdout, stderr = ssh.exec_command('ip firewall address-list enable [find list="BLOCKED_USERS"]')
        time.sleep(2)
        salida = stdout.read().decode()
        error = stderr.read().decode()
        
        ssh.close()
        
        if stderr.channel.recv_exit_status() != 0:
            print("Ocurrió un error al ejecutar el comando:", error)
        else:
            print("Comando ejecutado con éxito: \n", salida)
        
    except paramiko.ssh_exception.AuthenticationException as e:
        print('Autenticacion fallida')
    except socket.timeout as e:
        print("Error de Timeout: No se pudo establecer una conexión con el router en el tiempo especificado.")
    except socket.error as e:
        print("Error de conexión: No se pudo establecer una conexión con el router. Verifique la dirección IP.")
    except Exception as e:
        print(f"Error desconocido: {e}")
    
        
#nombre del archivo
localidad = input('Que localidad accederas: ')
#parametros para acceder al router
ip = input('Ingrese la ip del router: ')
user = input('Ingrese su usuario: ')
pw = getpass('Ingrese su password: ')


#llamada de las funciones 'accesoRouter' y 'leerIp'
datos =  accesoRouter(ip, user, pw)
guardarArchivo(datos, localidad +'.txt')
#llamada funcion disableIps e imprimir mensaje
deshabilitar = disableIps(ip, user, pw)
print(deshabilitar)
#busqueda de ips
encontrar = encontrarIps(localidad +'.txt')
#funcion 'conTelnet'
apagadoTv = conTelnet('root', 'root626', 'rootuser', '77553311', encontrar)
#funcion enable
habilitar = enableIps(ip, user, pw)