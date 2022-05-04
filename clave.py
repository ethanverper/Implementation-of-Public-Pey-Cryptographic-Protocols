from flask import Flask, render_template,request,send_from_directory
from ecdsa import VerifyingKey, NIST256p
from binascii import unhexlify
from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_nav import Nav
from flask_nav import elements
from flask_nav.elements import *
from dominate.tags import img
import ecdsa
from ecdsa import SigningKey
import pem
import PyPDF2
import hashlib
import numpy as np
import csv
from csv import writer
import pandas as pd
import codecs
from reportlab.pdfgen import canvas
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib import colors
from datetime import datetime
from tkinter import Tk, filedialog
import os
import shutil

def lectura_csv(nombre_csv):

  '''Función para leer los archivos CSV.
  Los datos se almacenan en una lista 
  llamada data. 
  nombre_csv = nombre del archivo csv.
  '''

  data = []
  with open(nombre_csv, mode ='r')as file:
   
    csvFile = csv.reader(file)
    for lines in csvFile:
      data.append(lines)
  
  return data

def texto_a_bytes(nom_archivo):

  '''Función que transforma las
  claves leídas en formato de texto a bytes 
  empleando encode de la librería codecs.
  nom_archivo = nombre del archivo a transformar.
  Para este caso archivos de clave tipo .pem.'''

  with open(nom_archivo,'r', encoding="utf-8") as key:
    key_bytes_pk = key.read()
  key_bytes_pk = codecs.encode(key_bytes_pk, 'latin1')

  return key_bytes_pk

def byte_a_texto(key):

  '''Función que transforma las claves 
  de la librería ECDSA a texto utilizando
  decode de la librería codecs. 
  key = llaves en formato objeto de ECDSA.'''

  p_key = key.to_string()
  p_key = codecs.decode(p_key, 'latin1')
  return p_key

def crear_claves(data, num_sujeto):

  '''Función que crea las claves públicas y
  privadas de un sujeto y cambia el estado a
  Activo.
  data = lista con los datos de los sujetos.
  num_sujeto = número de sujeto.'''

  private = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p,) 
  privatepem = private.to_pem()
  public = private.get_verifying_key()
  
  
  data[num_sujeto-1].append(public)
  data[num_sujeto-1].append('Activa')

  return data, privatepem, public

def archivo_key(num_archivo, key, name):

  '''Creación del archivo .pem para las 
  claves. 
  num_archivo = equivalente al número de sujeto.
  key = clave pública o privada.
  name = nombre del archivo. publicKey o privateKey. 
  '''
  
  name_a = name + str(num_archivo) + '.pem'
  if name == 'privateKey': 
     text_file = open(name_a, "wb")
     text_file.write(key)
     text_file.close()
  elif name == 'publicKey':
     text_file = open(name_a, "w", encoding="utf-8")
     text_file.write(byte_a_texto(key))
     text_file.close()

def cargar_base(data, nom_base):

  '''Función que carga la lista de datos
  recabados a la base de datos oficial que se 
  encuentra en formato csv.
  data = lista con los datos de los sujetos.
  nom_base = nombre de la base de datos oficial.
  '''

  for s_data in data:
    
    with open(nom_base, 'a', newline='', encoding="utf-8") as f_object:  
      writer_object = writer(f_object)
      writer_object.writerow(s_data)  
      f_object.close()

def revocar_firma(nom_file, data_frame, base_name):

  ''' Función para revocar firma de un sujeto 
  utilizando su clave pública. Se transforma la 
  clave a bits y se busca en el data frame de la base 
  de datos, se cambia el estado a Revocado.
  nom_file = archivo de la clave pública a revocar.
  data_frame = data frame de la base de datos.
  base_name = nombre de la base de datos oficial.
  '''
  
  public_key_r = str(texto_a_bytes(nom_file))
  data_frame.loc[data_frame.iloc[:,6] == public_key_r,'Estado'] = 'Revocado'
  data_frame.to_csv(base_name, index=False)
  return data_frame

def imp_certificado(num_s, data_c):

  '''Creación de los certificados a cada
  sujeto en formato pdf. 
  num_s = número de sujeto.
  data_c = lista de datos.'''

  nombre_doc = 'Certificado' + str(num_s) + '.pdf'
  titulo_doc = 'Certificado' + str(num_s) 
  titulo = 'Certificado'
  public_key = data_c[num_s-1][6].to_string()
  data_c[num_s-1][6] = codecs.decode(public_key, 'latin1')
  textLines = data_c[num_s-1]
  pdf = canvas.Canvas(nombre_doc)
  pdf.setTitle(titulo_doc)
  pdf.drawCentredString(300, 770, titulo)
  text = pdf.beginText(40, 680)
  for line in textLines:
    text.textLine(line)
  pdf.drawText(text)
  pdf.save()

  stringpublic = codecs.encode(data_c[num_s-1][6], 'latin1')
  returnpublic = VerifyingKey.from_string(stringpublic, curve=ecdsa.NIST256p)
  data_c[num_s-1][6] = returnpublic.to_string().hex()

def comprobar_caducidad(data_frame, base_name):

  '''Función para comprobar la caducidad
  de las claves generadas. Si la fecha actual es menor a
  la fecha 'No antes de', se marca como inválido. Si es 
  superior a 'No después de' se marca como expirado.
  data_frame = data frame de la base de datos.
  base_name = nombre de la base de datos.'''

  fecha_actual = datetime.now()

  data_frame.iloc[:,2]= pd.to_datetime(data_frame.iloc[:,2])
  data_frame.iloc[:,3]= pd.to_datetime(data_frame.iloc[:,3])

  data_frame.loc[data_frame.iloc[:,2] > fecha_actual,'Estado'] = 'Invalido'
  data_frame.loc[data_frame.iloc[:,3] < fecha_actual,'Estado'] = 'Expirado'

  data_frame.to_csv(base_name, index=False)


logo = img(src="https://th.bing.com/th/id/R.40105429b1191d9f6cf9c2c955a37dc5?rik=bVocPP4gd90pdg&riu=http%3a%2f%2f2.bp.blogspot.com%2f-CTRafEYZyf0%2fUqaAF318U1I%2fAAAAAAAAAMM%2fW8P-l3axB8c%2fs1600%2fLogo-Teleton-2013.png&ehk=C2AdorWtFr0zeUdwQcUT%2fiEi9CR6WYtJraavDVwDmsI%3d&risl=&pid=ImgRaw&r=0", 
    height="50", width="50", style="margin-top:-15px")

topbar = Navbar(logo,
                View('Generar Claves', 'claves'),
                View('Revocar Permisos', 'revocar')
                )

# registers the "top" menubar
nav = Nav()
nav.register_element('top', topbar)


app = Flask(__name__)
Bootstrap(app)


@app.route("/")
@app.route("/home", methods=['GET', 'POST'])
def home():
    return render_template("index.html")

@app.route("/claves", methods=['GET', 'POST'])
def claves():
    return render_template("claves.html")

@app.route("/revocar", methods=['GET', 'POST'])
def revocar():
    return render_template("revocar.html")

@app.route("/generar", methods=['GET', 'POST'])
def generar():
    #Guardar archivos del usuario
    usuarios = request.files["file5"]
    if usuarios != '':
        usuarios.save('Prueba3.csv')

    try:
        datos_prueba = 'Prueba3.csv'
        data = lectura_csv(datos_prueba)

        # Loop para cada uno de los sujetos en los datos de prueba.
        for i in range(1, len(data)+1):
            data, private, public = crear_claves(data, i) 
            # Creación de la lista de datos, la public y private key.
            archivo_key(i, private, 'privateKey')
            # Creación del archivo de la private key.
            archivo_key(i, public, 'publicKey')
            # Creación del archivo de la public key.
            imp_certificado(i, data)
            # Creación del certificado.
        nombre_base = 'data_base.csv'
        cargar_base(data, nombre_base) #Se carga la información a la base de datos.
        usuarios_result = render_template("pathdescarga.html", name='La clave ha sido generada.')
    except:
        usuarios_result = render_template("resultado.html", name='El archivo introducido es incorrecto.')

    return usuarios_result

@app.route("/descarga", methods=['GET', 'POST'])
def descarga():
    from tkinter import Tk, filedialog
    root = Tk() # pointing root to Tk() to use it as Tk() in program.
    root.withdraw() # Hides small tkinter window.
    root.attributes('-topmost', True) # Opened windows will be active. above all windows despite of selection.
    open_file = filedialog.askdirectory() # Regresa el path que el usuario eligio para gurdar los archivos   
    shutil.copy('privateKey1.pem', open_file)
    os.remove('privateKey1.pem')
    shutil.copy('publicKey1.pem', open_file)
    os.remove('publicKey1.pem')
    shutil.copy('Certificado1.pdf', open_file)
    os.remove('Certificado1.pdf')
    final = 'El archivo ha sido guardado en la carpeta seleccionada: '# + open_file
     
    return render_template("resultado2.html", name=final)

@app.route("/eliminar", methods=['GET', 'POST'])
def eliminar():
    #Guardar archivos del usuario
    clave = request.files["file6"]
    if clave != '':
        clave.save('publicKey.pem')

    try:
        prueba_revocar = 'publicKey.pem'
        base = pd.read_csv('data_base.csv') # name=column
        nombre_base = 'data_base.csv'
        base = revocar_firma(prueba_revocar, base, nombre_base) 

        revocar_result = 'Los permisos del usuario han sido revocados.'
    except:
        revocar_result = 'La clave introducida es incorrecta.'

    return render_template("resultado.html", name=revocar_result)


nav.init_app(app)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
