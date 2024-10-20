import mysql.connector

# Función para conectar a la base de datos
def conectar_bd():
    return mysql.connector.connect(
        user='root',
        password='panepe22',
        host='localhost',
        database='entrada',
        port='3306'
    )

# Función para verificar las credenciales
def verificar_credenciales(usuario, contraseña):
    conexion = conectar_bd()
    cursor = conexion.cursor()
    query = "SELECT * FROM accesologin WHERE username = %s AND password = %s"
    cursor.execute(query, (usuario, contraseña))
    resultado = cursor.fetchone()
    cursor.close()
    conexion.close()
    return resultado is not None

# Solicitar credenciales al usuario
usuario = input("Ingrese su nombre de usuario: ")
contraseña = input("Ingrese su contraseña: ")

# Verificar las credenciales
if verificar_credenciales(usuario, contraseña):
    print("Login exitoso")
else:
    print("Usuario o contraseña incorrectos")
