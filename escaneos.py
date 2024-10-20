# Importación de módulos necesarios
import socket  # Para crear conexiones de red
import threading  # Para ejecutar tareas en paralelo
import re  # Para usar expresiones regulares
import struct  # Para trabajar con estructuras de datos binarias

# Listas globales para almacenar información
hilos = []  # Lista para almacenar los hilos de ejecución
PUERTOSM = []  # Lista para almacenar puertos (no se usa en este fragmento)
PUERTOS_ABIERTOS2 = []  # Lista alternativa para puertos abiertos (no se usa en este fragmento)

def escanear_puerto(IP, PUERTO, PUERTOS_ABIERTOS):
    """
    Función para escanear un puerto específico en una dirección IP dada.
    
    Args:
    IP (str): La dirección IP a escanear.
    PUERTO (int): El número de puerto a escanear.
    PUERTOS_ABIERTOS (list): Lista para almacenar los puertos abiertos encontrados.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Establece un tiempo de espera de 1 segundo

    resultado = sock.connect_ex((IP, PUERTO))
    if resultado == 0:  # Si la conexión es exitosa, el puerto está abierto
        PUERTOS_ABIERTOS.append(PUERTO)
        print(f"Puerto {PUERTO} está abierto")
    sock.close()

def escanear_puertos(IP, puerto_inicial, puerto_final):
    """
    Función para escanear un rango de puertos en una dirección IP dada.
    
    Args:
    IP (str): La dirección IP a escanear.
    puerto_inicial (int): El primer puerto del rango a escanear.
    puerto_final (int): El último puerto del rango a escanear.
    
    Returns:
    list: Una lista ordenada de puertos abiertos sin duplicados.
    """
    PUERTOS_ABIERTOS = []
    hilos = []

    # Crea y inicia un hilo para cada puerto en el rango
    for PUERTO in range(puerto_inicial, puerto_final + 1):
        thread = threading.Thread(target=escanear_puerto, args=(IP, PUERTO, PUERTOS_ABIERTOS))
        hilos.append(thread)
        thread.start()

    # Espera a que todos los hilos terminen
    for thread in hilos:
        thread.join()

    PUERTOS_ABIERTOS = list(set(PUERTOS_ABIERTOS))  # Eliminar duplicados
    PUERTOS_ABIERTOS.sort()  # Ordenar la lista
    return PUERTOS_ABIERTOS


def servicios(IP, PUERTOS_ABIERTOS):
    """
    Función para detectar y identificar servicios en puertos específicos de una dirección IP.

    Args:
    IP (str): La dirección IP a escanear.
    PUERTOS_ABIERTOS (list): Lista de puertos abiertos en la IP dada.

    Returns:
    list: Una lista de servicios detectados con sus versiones (si es posible).
    """
    servicios = []
    serviciosC = []

# Detección de servidor HTTP (puerto 80)
    if 80 in PUERTOS_ABIERTOS:
        try:
            # Crear un socket TCP/IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Establecer un tiempo de espera de 5 segundos para la conexión
            sock.settimeout(5)
            # Intentar conectar al puerto 80 de la IP especificada
            sock.connect((IP, 80))
            
            # Preparar una solicitud HTTP GET básica
            solicitud = b"GET / HTTP/1.1\r\nHost: " + IP.encode() + b"\r\n\r\n"
            # Enviar la solicitud HTTP
            sock.send(solicitud)
            
            # Recibir la respuesta del servidor (máximo 1024 bytes)
            # Decodificar la respuesta, ignorando caracteres que no puedan ser decodificados
            respuesta = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Cerrar la conexión
            sock.close()
            
            # Verificar si la respuesta contiene "HTTP", indicando que es un servidor web
            if "HTTP" in respuesta:
                # Buscar la cabecera "Server" en la respuesta usando una expresión regular
                match = re.search(r'Server:\s*([^\r\n]+)', respuesta)
                if match:
                    servidor = match.group(1).strip()
                    servicios.append(f"Apache/{servidor}")
                    # Formato simplificado para serviciosC
                    version = servidor.split('/')[1].split()[0]  # Toma solo la versión numérica
                    if version:
                        serviciosC.append(f"Apache {version}")
                print(f"Servidor HTTP detectado: {servidor}")
            else:
                servicios.append("HTTP/Versión no determinada")
        except Exception as e:
            print(f"Error al conectar al puerto 80: {e}")
                    

        # Detección de servidor FTP (puerto 21)
        # Detección de servidor FTP (puerto 21)
    if 21 in PUERTOS_ABIERTOS:
        try:
            # Crear un socket TCP/IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Establecer un tiempo de espera de 5 segundos para la conexión
            sock.settimeout(5)
            # Intentar conectar al puerto 21 de la IP especificada
            sock.connect((IP, 21))
            
            # Recibir el mensaje de bienvenida del servidor FTP (máximo 1024 bytes)
            # Decodificar la respuesta, ignorando caracteres que no puedan ser decodificados
            respuesta = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Cerrar la conexión
            sock.close()
            
            # Verificar si la respuesta contiene "FTP", indicando que es un servidor FTP
            if "FTP" in respuesta:
                # Buscar la versión del servidor FTP en la respuesta usando una expresión regular
                # El patrón busca el contenido entre paréntesis después del código 220
                match = re.search(r'220[^\r\n]*\(([^)]+)\)', respuesta)
                if match:
                    servidor_ftp = match.group(1).strip()
                    servicios.append(f"FTP/{servidor_ftp}")
                    # Formato simplificado para serviciosC
                    if servidor_ftp:
                        serviciosC.append(f"{servidor_ftp}")
                    print(f"Servidor FTP detectado: {servidor_ftp}")
                else:
                    servicios.append("FTP/Versión no determinada")
                    # No añadimos nada a serviciosC si no podemos determinar la versión
        except Exception as e:
            print(f"Error al conectar al puerto 21: {e}")

    # Detección de servidor SSH (puerto 22)
    if 22 in PUERTOS_ABIERTOS:
        try:
            # Crear un socket TCP/IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Establecer un tiempo de espera de 5 segundos para la conexión
            sock.settimeout(5)
            # Intentar conectar al puerto 22 de la IP especificada
            sock.connect((IP, 22))
            # Recibir la respuesta del servidor SSH y decodificarla
            respuesta = sock.recv(1024).decode('utf-8', errors='ignore')
            # Cerrar la conexión
            sock.close()
            # Patrón para buscar la versión de OpenSSH
            patron = r"SSH-\d+\.\d+-(OpenSSH_\d+\.\d+p\d+)"
            # Buscar el patrón en la respuesta
            coincidencia = re.search(patron, respuesta)
            if coincidencia:
                ssh_version = coincidencia.group(1)
                servicios.append(f"SSH/{ssh_version}")
                # Formato simplificado para serviciosC
                version = ssh_version.split('_')[1]
                if version:
                    serviciosC.append(f"OpenSSH {version}")
                print(f"Servidor SSH detectado: {ssh_version}")
            else:
                servicios.append("SSH/Versión no determinada")
                # No añadimos nada a serviciosC si no podemos determinar la versión
        except Exception as e:
            print(f"Error al conectar al puerto 22: {e}")

    # Detección de servidor MySQL (puerto 3306)
    if 3306 in PUERTOS_ABIERTOS:
        try:
            print("Puerto 3306 (MySQL) está abierto")
            # Crear un socket TCP/IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Establecer un tiempo de espera de 5 segundos para la conexión
            sock.settimeout(5)
            # Intentar conectar al puerto 3306 de la IP especificada
            sock.connect((IP, 3306))
            
            # Recibir el paquete de saludo de MySQL
            packet = sock.recv(1024)
            
            if packet:
                if len(packet) >= 5:
                    # Extraer la longitud del paquete y el ID de secuencia
                    pkt_len = struct.unpack('<I', packet[:3] + b'\x00')[0]
                    seq_id = struct.unpack('<B', packet[3:4])[0]
                    
                    # Verificar si el paquete es válido
                    if pkt_len == len(packet) - 4 and seq_id == 0:
                        # Buscar la posición del byte nulo que separa la versión
                        null_pos = packet[5:].find(b'\x00')
                        if null_pos != -1:
                            version = packet[5:5+null_pos].decode('ascii')
                            servicios.append(f"MySQL/{version}")
                            # Formato simplificado para serviciosC
                            version_simple = version.split('-')[0]  # Toma solo la versión numérica
                            if version_simple:
                                serviciosC.append(f"MySQL {version_simple}")
                            print(f"Servidor MySQL detectado: {version}")
                        else:
                            servicios.append("MySQL/Versión no determinada")
                            print("Servidor MySQL detectado (versión no determinada)")
                    else:
                        servicios.append("MySQL/Versión no determinada")
                        print("Servidor MySQL detectado (versión no determinada)")
                else:
                    servicios.append("MySQL/Versión no determinada")
                    print("Servidor MySQL detectado (versión no determinada)")
            else:
                servicios.append("Posible MySQL (sin respuesta)")
                print("Posible servidor MySQL (sin respuesta)")
            
            # Cerrar la conexión
            sock.close()
        except Exception as e:
            # Capturar y mostrar cualquier error que ocurra durante el proceso
            print(f"Error al conectar al puerto 3306: {e}")
            servicios.append("Posible MySQL (error de conexión)")
            print("Posible servidor MySQL (error de conexión)")
        # Detección de servidor SMB (puerto 445)
    # Detección de servidor SMB (puerto 445)
    if 445 in PUERTOS_ABIERTOS:
        try:
            # Crear un socket TCP/IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Establecer un tiempo de espera de 5 segundos para la conexión
            sock.settimeout(5)
            # Intentar conectar al puerto 445 de la IP especificada
            sock.connect((IP, 445))
            
            # Preparar una solicitud SMB Negotiate Protocol
            # Preparar una solicitud SMB Negotiate Protocol
            smb_negotiate = (
                b"\x00\x00\x00\x85"  # Servicio de Sesión NetBIOS
                b"\xff\x53\x4d\x42"  # Encabezado SMB: Componente del Servidor: SMB
                b"\x72"              # Comando SMB: Negociar Protocolo (0x72)
                b"\x00\x00\x00\x00"  # Estado NT: ESTADO_EXITOSO
                b"\x18\x53\xc0"      # Banderas
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
                b"\x00\x00"          # ID de Proceso Alto
                b"\x40\x00"          # Firma
                b"\x00\x62"          # Reservado
                b"\x00\x02"          # ID de Árbol
                b"\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"
                b"\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
                b"\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00"
                b"\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"
                b"\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00"
                b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
            )
            
            # Enviar la solicitud SMB Negotiate Protocol
            sock.send(smb_negotiate)
            # Recibir la respuesta del servidor
            respuesta = sock.recv(1024)
            # Cerrar la conexión
            sock.close()
            
            if respuesta:
                # Verificar si la respuesta tiene la firma SMB correcta
                if respuesta[4:8] == b'\xff\x53\x4d\x42':
                    version = "SMB"
                    if len(respuesta) >= 72:
                        dialect_index = struct.unpack("<H", respuesta[70:72])[0]
                    if dialect_index == 5:
                        version = "Samba"
                        samba_version = re.search(b"Samba ([0-9.]+)", respuesta)
                        if samba_version:
                            version = f"Samba {samba_version.group(1).decode()}"
                    
                    # Añadir el servicio SMB detectado a la lista
                    servicios.append(f"netbios-ssn {version}")
                    # Formato simplificado para serviciosC
                    if version:
                        serviciosC.append(f"{version}")
                    print(f"Puerto 445: netbios-ssn {version}")
                else:
                    # Si la firma no coincide, podría ser una implementación no estándar de SMB
                    servicios.append("Posible SMB (respuesta no estándar)")
                    print("Puerto 445: Posible SMB (respuesta no estándar)")
            else:
                # Si no hay respuesta, podría ser un servidor SMB que no responde a la negociación
                servicios.append("Posible SMB (sin respuesta)")
                print("Puerto 445: Posible SMB (sin respuesta)")
        except Exception as e:
            # Capturar y mostrar cualquier error que ocurra durante el proceso
            print(f"Error al conectar al puerto 445: {e}")
            servicios.append("Posible SMB (error de conexión)")
            print("Puerto 445: Posible SMB (error de conexión)")

    # Devolver la lista de servicios 
    return servicios, serviciosC
