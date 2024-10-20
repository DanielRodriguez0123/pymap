import socket
import logging
import escaneos
import paginaweb
import requests
import time
from deep_translator import GoogleTranslator

def vulnerabilidadesFTP(IP):
    vulnerabilidadesList = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((IP, 21))
        
        # Recibir el banner inicial
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"Banner FTP: {banner.strip()}")
        
        # Intentar login anónimo
        sock.send(b"USER anonymous\r\n")
        respuesta = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"Respuesta a USER: {respuesta.strip()}")
        
        if "331" in respuesta:  # 331 significa que el servidor está esperando la contraseña
            sock.send(b"PASS anonymous@\r\n")
            respuesta = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"Respuesta a PASS: {respuesta.strip()}")
            
            if "230" in respuesta:  # 230 significa login exitoso
                vulnerabilidad = "Advertencia: el servidor FTP admite conexiones anónimas."
                vulnerabilidadesList.append(vulnerabilidad)
                print(vulnerabilidad)
                logging.warning(f"IP {IP}: {vulnerabilidad}")
            elif "530" in respuesta:  # 530 significa login fallido
                print("El servidor FTP no admite conexiones anónimas.")
            else:
                print(f"Respuesta inesperada del servidor FTP: {respuesta.strip()}")
        else:
            print("El servidor FTP no respondió como se esperaba al intento de login anónimo.")
        
        sock.close()
    except Exception as e:
        print(f"Error al conectar al puerto 21: {e}")
        logging.error(f"IP {IP}: Error al conectar al puerto 21 - {e}")
    
    return vulnerabilidadesList


def vulnerabilidadesSMB(IP):
    vulnerabilidadesList = []
    print(f"Consultando SMB para {IP}:")
    
    # Utilizamos la función de detección de SMB de escaneos.py
    smb_info = escaneos.servicios(IP, [445])
    
    for servicio in smb_info:
        if "SMB" in servicio or "Samba" in servicio:
            print(f"Servicio SMB detectado: {servicio}")
            logging.info(f"IP {IP}: Servicio SMB detectado - {servicio}")
            
            # Aquí puedes agregar lógica para detectar vulnerabilidades específicas de SMB
            # Por ejemplo:
            if "SMB 1.0" in servicio:
                vulnerabilidad = "Vulnerabilidad: SMB 1.0 detectado (potencialmente vulnerable a EternalBlue)"
                vulnerabilidadesList.append(vulnerabilidad)
                logging.warning(f"IP {IP}: {vulnerabilidad}")
            break
    else:
        print("No se detectó servicio SMB en el puerto 445.")
        logging.info(f"No se detectó servicio SMB en el puerto 445 para IP {IP}")

    # Intentar obtener el nombre de host
    try:
        hostname = socket.gethostbyaddr(IP)[0]
        vulnerabilidad = f"Nombre de host: {hostname}"
        vulnerabilidadesList.append(vulnerabilidad)
        print(vulnerabilidad)
        logging.info(f"IP {IP}: {vulnerabilidad}")
    except socket.herror:
        print("No se pudo obtener el nombre de host")
    
    return vulnerabilidadesList

def generar_recomendaciones(vulnerabilidades):
    recomendaciones = []
    for vulnerabilidad in vulnerabilidades:
        if "el servidor FTP admite conexiones anónimas" in vulnerabilidad:
            recomendaciones.append("Desactivar el acceso FTP anónimo: Edite el archivo de configuración del servidor FTP (como vsftpd.conf) y establezca 'anonymous_enable=NO'.")
        elif "SMB 1.0 detectado" in vulnerabilidad:
            recomendaciones.append("Deshabilitar SMB 1.0: Use el Administrador del servidor para desactivar SMB 1.0 y habilitar versiones más recientes como SMB 2.0 o 3.0.")
        # Añade más recomendaciones según las vulnerabilidades detectadas
        
    return recomendaciones

def imprimir_banner(servicio):
    ancho = max(len(servicio) + 4, 50)  # Asegura un ancho mínimo de 50 caracteres
    print("\n" + "-" * ancho)
    print(f"|{servicio.center(ancho-2)}|")
    print("-" * ancho)

def detectar_vulnerabilidades_nvd(serviciosC):
    vulnerabilidades_nvd = []
    translator = GoogleTranslator(source='en', target='es')

    for servicio in serviciosC:
        imprimir_banner(servicio)
        
        nvdCVEs = servicio.replace(" ", "%20")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={nvdCVEs}"

        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                for vulnerability in vulnerabilities:
                    cve_id = vulnerability.get("cve", {}).get("id")
                    descriptions = vulnerability.get("cve", {}).get("descriptions", [])
                    if descriptions:
                        description = next((desc.get("value") for desc in descriptions if desc.get("lang") == "en"), "No English description available")
                        if len(description) > 450:
                            description = description[:450] + "..."
                        try:
                            description_es = translator.translate(description)
                        except Exception as e:
                            print(f"Error en la traducción: {e}")
                            description_es = description  # Usar la descripción en inglés si hay un error
                    else:
                        description = "No description available"
                        description_es = "No hay descripción disponible"
                    
                    vuln_info = f"CVE ID: {cve_id}\nDescripción: {description_es}"
                    vulnerabilidades_nvd.append(vuln_info)
                    print(vuln_info)
                    print("---")
                    time.sleep(1)  # Añadir un pequeño retraso entre traducciones
            else:
                print("No se encontraron vulnerabilidades para este servicio.")
        except requests.RequestException as e:
            print(f"Error al consultar la API de NVD: {e}")
            logging.error(f"Error al consultar la API de NVD para {servicio}: {e}")

    return vulnerabilidades_nvd

def detectar_vulnerabilidades(IP):
    print(f"Detectando vulnerabilidades para {IP}...")
    
    puerto_inicial = 1
    puerto_final = 1024
    puertos_abiertos = escaneos.escanear_puertos(IP, puerto_inicial, puerto_final)
    
    servicios_encontrados = escaneos.servicios(IP, puertos_abiertos)
    
    vulns = []
    
    # Detectar vulnerabilidades FTP
    vulns_ftp = vulnerabilidadesFTP(IP)
    vulns.extend(vulns_ftp)
    
    # Detectar vulnerabilidades SMB
    vulns_smb = vulnerabilidadesSMB(IP)
    vulns.extend(vulns_smb)
    
    print("\nResultados de la detección de vulnerabilidades:")
    print(f"Puertos abiertos: {puertos_abiertos}")
    print("Servicios encontrados:")
    for servicio in servicios_encontrados:
        print(f"- {servicio}")
    print("Vulnerabilidades detectadas:")
    for vuln in vulns:
        print(f"- {vuln}")
    
    recomendaciones = generar_recomendaciones(vulns)
    
    paginaweb.generar_reporte_html(IP, puertos_abiertos, servicios_encontrados, vulns, recomendaciones)
    print(f"\nReporte HTML generado para {IP}")
    
    input("\nPresione Enter para continuar...")

