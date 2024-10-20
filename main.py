import os
import sys
import ctypes
import paginaweb
import escaneos
import vulnerabilidades
import mysql.connector
import logging
from vulnerabilidades import detectar_vulnerabilidades
from vulnerabilidades import detectar_vulnerabilidades_nvd

MENU_PRINCIPAL = """
-----------------------------------------------------------------------------------------------
|                                           Menu                                                |
|_______________________________________________________________________________________________|
|1._ Ingresar IP                                                                                |
|2._ Salir                                                                                      |
|_______________________________________________________________________________________________|
"""

MENU_ESCANEO = """
-----------------------------------------------------------------------------------------------
|                                           Menu                                                |
|_______________________________________________________________________________________________|
|1._ Escaneo completo                                                                           |
|2._ Escanear puertos                                                                           |
|3._ Escanear servicios                                                                         |
|4._ Detectar vulnerabilidades                                                                  |
|_______________________________________________________________________________________________|
"""

MENU_PUERTOS = """
-----------------------------------------------------------------------------------------------
|                                           Menu                                                |
|_______________________________________________________________________________________________|
|1._ Ingresar rango de puertos                                                                  |
|2._ Ingresar puertos manualmente                                                               |
|_______________________________________________________________________________________________|
"""

# Configuración de logging
logging.basicConfig(filename='scanner.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def cls():
    """Limpia la pantalla de la consola."""
    os.system("cls" if os.name == "nt" else "clear")

def es_administrador():
    """Verifica si el script se está ejecutando con privilegios de administrador."""
    if os.name == "nt":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.getuid() == 0

def banner():
    """Muestra el banner del programa."""
    print("""
░       ░░        ░░      ░░  ░░░░  ░        ░       ░░░      ░░░      ░░░      ░░   ░░░  ░░░░░░
▒  ▒▒▒▒  ▒  ▒▒▒▒▒▒▒  ▒▒▒▒  ▒  ▒▒▒▒  ▒  ▒▒▒▒▒▒▒  ▒▒▒▒  ▒  ▒▒▒▒▒▒▒  ▒▒▒▒  ▒  ▒▒▒▒  ▒    ▒▒  ▒▒▒▒▒▒
▓       ▓▓      ▓▓▓  ▓▓▓▓  ▓▓  ▓▓  ▓▓      ▓▓▓       ▓▓▓      ▓▓  ▓▓▓▓▓▓▓  ▓▓▓▓  ▓  ▓  ▓  ▓▓▓▓▓▓
█  ████  █  ███████        ███    ███  ███████  ███  ████████  █  ████  █        █  ██    ██████
█       ██        █  ████  ████  ████        █  ████  ██      ███      ██  ████  █  ███   ██████
    """)

def conectar_bd():
    """Conecta a la base de datos MySQL."""
    try:
        return mysql.connector.connect(
            user='root',
            password='panepe22',
            host='localhost',
            database='entrada',
            port='3306'
        )
    except mysql.connector.Error as err:
        logging.error(f"Error al conectar a la base de datos: {err}")
        sys.exit(1)

def verificar_credenciales(usuario, contraseña):
    """Verifica las credenciales del usuario en la base de datos."""
    conexion = conectar_bd()
    cursor = conexion.cursor()
    query = "SELECT * FROM accesologin WHERE username = %s AND password = %s"
    cursor.execute(query, (usuario, contraseña))
    resultado = cursor.fetchone()
    cursor.close()
    conexion.close()
    return resultado is not None

from vulnerabilidades import vulnerabilidadesFTP, vulnerabilidadesSMB

def escaneo_completo(IP):
    print(f"Iniciando escaneo completo para la IP: {IP}")
    puerto_inicial = int(input("Ingrese el puerto inicial: "))
    puerto_final = int(input("Ingrese el puerto final: "))
    print(f"Escaneando puertos en {IP} desde {puerto_inicial} hasta {puerto_final}...")
    
    puertos_abiertos = escaneos.escanear_puertos(IP, puerto_inicial, puerto_final)
    if puertos_abiertos:
        print(f"Puertos abiertos en {IP}: {puertos_abiertos}")
        logging.info(f"Puertos abiertos encontrados en {IP}: {puertos_abiertos}")
    else:
        print(f"No se encontraron puertos abiertos en {IP}.")
        logging.info(f"No se encontraron puertos abiertos en {IP}")
    
    servicios_encontrados, serviciosC = escaneos.servicios(IP, puertos_abiertos)
    print("\nServicios encontrados:")
    for servicio in servicios_encontrados:
        print(servicio)
    logging.info(f"Servicios encontrados en {IP}: {servicios_encontrados}")

    print("\nServicios en formato simplificado (serviciosC):")
    for servicio in serviciosC:
        print(servicio)
    logging.info(f"Servicios simplificados en {IP}: {serviciosC}")

    vulns = []
    
    # Verificar vulnerabilidades FTP
    vulns_ftp = vulnerabilidades.vulnerabilidadesFTP(IP)
    if vulns_ftp:
        vulns.extend(vulns_ftp)
        print("\nVulnerabilidades FTP detectadas:")
        for vuln in vulns_ftp:
            print(vuln)
        logging.info(f"Vulnerabilidades FTP detectadas en {IP}: {vulns_ftp}")
    else:
        print("No se detectaron vulnerabilidades FTP.")
        logging.info(f"No se detectaron vulnerabilidades FTP en {IP}")


    # Verificar vulnerabilidades SMB
    vulns_smb = vulnerabilidades.vulnerabilidadesSMB(IP)
    if vulns_smb:
        vulns.extend(vulns_smb)
        print("\nVulnerabilidades SMB detectadas:")
        for vuln in vulns_smb:
            print(vuln)
        logging.info(f"Vulnerabilidades SMB detectadas en {IP}: {vulns_smb}")
    else:
        print("No se detectaron vulnerabilidades SMB.")
        logging.info(f"No se detectaron vulnerabilidades SMB en {IP}")
# Detectar vulnerabilidades usando NVD
    vulns_nvd = detectar_vulnerabilidades_nvd(serviciosC)
    if vulns_nvd:
        vulns.extend(vulns_nvd)
        print("\nVulnerabilidades detectadas por NVD:")
        for vuln in vulns_nvd:
            print(vuln)
        logging.info(f"Vulnerabilidades detectadas por NVD en {IP}: {vulns_nvd}")
    else:
        print("No se detectaron vulnerabilidades adicionales por NVD.")
        logging.info(f"No se detectaron vulnerabilidades adicionales por NVD en {IP}")

    if vulns:
        print("\nResumen de vulnerabilidades detectadas:")
        for vuln in vulns:
            print(vuln)
        logging.info(f"Total de vulnerabilidades detectadas en {IP}: {len(vulns)}")
    else:
        print("\nNo se detectaron vulnerabilidades.")
        logging.info(f"No se detectaron vulnerabilidades en {IP}")
    
    
    recomendaciones = vulnerabilidades.generar_recomendaciones(vulns)
    
    paginaweb.generar_reporte_html(IP, puertos_abiertos, servicios_encontrados, vulns, recomendaciones, serviciosC)
    logging.info(f"Reporte HTML generado para {IP}")
    
    input("\nPresione Enter para continuar...")


def escaneoPuertos(IP):
    cls()
    banner()
    PUERTO_I = int(input("Ingrese el puerto inicial: >_ "))
    PUERTO_F = int(input("Ingrese el puerto final: >_ "))
    print(f"Escaneado puertos en {IP} desde {PUERTO_I} hasta {PUERTO_F}...")
    logging.info(f"Escaneando puertos en {IP} desde {PUERTO_I} hasta {PUERTO_F}")
    PUERTOS_ABIERTOS = escaneos.escanear_puertos(IP, PUERTO_I, PUERTO_F)
    print(type(PUERTOS_ABIERTOS))
    if PUERTOS_ABIERTOS:
        print("""
    ------------------------------------------------------------------------
                                    Puertos
    ------------------------------------------------------------------------
    """)
        print(f"Puertos abiertos en {IP}: {PUERTOS_ABIERTOS}")
        logging.info(f"Puertos abiertos encontrados en {IP}: {PUERTOS_ABIERTOS}")
    else:
        print(f"No se encontraron puertos abiertos en {IP}.")
    logging.info(f"No se encontraron puertos abiertos en {IP}")
    paginaweb.generar_reporte_html(IP, PUERTOS_ABIERTOS, " ", " ")
    logging.info(f"Reporte HTML generado para {IP}")


def escaneo_servicios(IP):
    cls()
    banner()
    print(MENU_PUERTOS)
    puertosR = int(input("Selecciona una opción: "))
    if puertosR == 1:
        PUERTO_I = int(input("Ingrese el puerto inicial: "))
        PUERTO_F = int(input("Ingrese el puerto final: "))
        PUERTOS_ABIERTOS = escaneos.escanear_puertos(IP, PUERTO_I, PUERTO_F)
    elif puertosR == 2:
        puertosM = input("Escriba los puertos con los que desea trabajar separados por comas (ejemplo: 1,2,3,4,5): ")
        puertos_a_escanear = [int(puerto) for puerto in puertosM.split(',')]
        PUERTOS_ABIERTOS = escaneos.escanear_puertos(IP, min(puertos_a_escanear), max(puertos_a_escanear))
    else:
        print("Opción no válida")
        return

    servicios_encontrados, serviciosC = escaneos.servicios(IP, PUERTOS_ABIERTOS)
    print("""
    ------------------------------------------------------------------------
                                    Servicios
    ------------------------------------------------------------------------
    """)
    for servicio in servicios_encontrados:
        print(servicio)
    print("\nServicios en formato simplificado (serviciosC):")
    for servicio in serviciosC:
        print(servicio)
    paginaweb.generar_reporte_html(IP, PUERTOS_ABIERTOS, servicios_encontrados, [], [], serviciosC)
    
    # Añadir esta línea para esperar la entrada del usuario antes de continuar
    input("\nPresione Enter para continuar...")

def menu():
    """Función principal que maneja el menú y el flujo del programa."""
    usuario = input("Ingrese su nombre de usuario: ")
    contraseña = input("Ingrese su contraseña: ")

    if verificar_credenciales(usuario, contraseña):
       logging.info(f"Login exitoso para el usuario: {usuario}")
       banner()
       if not es_administrador():
           print("Este script debe ejecutarse con privilegios de administrador")
           logging.warning("Intento de ejecución sin privilegios de administrador")
           sys.exit(1)

       while True:
        cls()
        print(MENU_PRINCIPAL)
        opcion = input("Ingrese una opción: ")

        if opcion == '1':
            IP = input("Ingrese la IP: ")
            logging.info(f"Usuario {usuario} iniciando pruebas en la IP: {IP}")
            cls()
            print(MENU_ESCANEO)
            tipo_escaneo = input("Ingrese qué desea hacer: ")

            if tipo_escaneo == '1':
                escaneo_completo(IP)
            elif tipo_escaneo == '2':
                # Implementar escaneo de puertos
                escaneoPuertos(IP)
            elif tipo_escaneo == '3':
                # Implementar escaneo de servicios
                escaneo_servicios(IP)
            elif tipo_escaneo == '4':
                # Implementar detección de vulnerabilidades
                detectar_vulnerabilidades(IP)
            else:
                print("Opción no válida")

        elif opcion == '2':
            print("Saliendo...")
            break
        else:
            print("Opción no válida")

        input("presione enter para continuar")

    else:
        print("Usuario o contraseña incorrectos")
        logging.warning(f"Intento de login fallido para el usuario: {usuario}")

if __name__ == "__main__":
    menu()