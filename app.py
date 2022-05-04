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

  with open(nom_archivo,'r') as key:
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
     text_file = open(name_a, "w")
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
    
    with open(nom_base, 'a', newline='') as f_object:  
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
                View('Firma', 'firma'),
                View('Verificación', 'verificacion')
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

@app.route("/firma", methods=['GET', 'POST'])
def firma():
    return render_template("firma.html")

@app.route("/verificacion", methods=['GET', 'POST'])
def verificacion():
    return render_template("verificacion.html")

@app.route("/result", methods=['GET', 'POST'])
def result():
    #Guardar archivos del usuario
    clave = request.files["file1"]
    documento = request.files["file2"]
    if clave.filename != '' and documento.filename != '':
        clave.save('private.pem')
        documento.save('documento.pdf')
    try:
      #Se lee el archivo (mensaje) que el usuario quiere firmar, son de tipo pdf
      archivo = open("documento.pdf", "rb")
      # lo lee y guarda en bytes en la variable contenido
      contenido = archivo.read()
      archivo.close()
      os.remove('documento.pdf')

      #Leer archivo pem
      priv = open('private.pem', 'r')
      priv = priv.read()
      priv = priv.encode()
      #Obetener clave privada
      private_key = SigningKey.from_pem(priv)
      # Aqui volvemos a generar la public key a partir de la private key para la comprobación
      public_key = private_key.get_verifying_key()#.to_string().hex()

      #cargar base de datos
      base = pd.read_csv('data_base.csv')
      comprobar_caducidad(base,'data_base.csv')
    
      try:
        #checar si la clave es valida
          cond = (base['Clave Publica'] == public_key.to_string().hex())
          match = base.loc[cond]

          #firma
          if (match['Estado'] == 'Activa').bool():
              # Se genera la firma con private_key y la función '.sign'
              # en la función se pone el mensaje obtenido del pdf y se pone el tipo de hash que se utiliza
              # en este caso usamos sha256
              sig = private_key.sign(contenido, hashfunc=hashlib.sha256)
              #guardar firma y clave publica .pem
              firma_hex = sig.hex()
              public_hex = public_key.to_string().hex()
              ## Creación del archivo que contendrá la firma
              with open('firma_certificado.pem', 'w') as file:
                  file.write("%s %s\n" % (firma_hex, public_hex))
              final= render_template("pathdescarga.html", name='El archivo ha sido firmado.')
          else: 
              final = render_template("resultado.html", name='La clave no se encuentra activa.')
      except:
        final = render_template("resultado.html", name='La clave que se introdujo no es válida.')
    except:
      final = render_template("resultado.html", name='Los archivos utilizados no son válidos.')
    os.remove('private.pem')
    return final

@app.route("/descarga", methods=['GET', 'POST'])
def descarga():
    from tkinter import Tk, filedialog
    root = Tk() # pointing root to Tk() to use it as Tk() in program.
    root.withdraw() # Hides small tkinter window.
    root.attributes('-topmost', True) # Opened windows will be active. above all windows despite of selection.
    open_file = filedialog.askdirectory() # Returns opened path as str
    #print(open_file) 
    #os.mkdir(open_file)
    #descarga = send_from_directory(directory='../flask/', filename='firma_clavepublica.pem', as_attachment=True)     
    shutil.copy('firma_certificado.pem', open_file)
    os.remove('firma_certificado.pem')
    final = 'El archivo ha sido guardado en la carpeta seleccionada: '# + open_file
     
    return render_template("resultado2.html", name=final)

@app.route("/result2", methods=['GET', 'POST'])
def result2():
    #Guardar archivos del usuario
    firma_y_clave = request.files["file3"]
    documento = request.files["file4"]
    if firma_y_clave.filename != '' and documento.filename != '':
        firma_y_clave.save('firma_y_clave.pem')
        documento.save('documento2.pdf')

    try:
        # Extrae firma y clave publica del archivo .pem
        # lo guarda como texto
        string = open('firma_y_clave.pem', 'r')
        string = string.read()
        #lo guarda en una lista para separar la firma de la public key
        lista = string.split()

        #Toma la public key de la lista y lo guarda en la variable public_verify
        public_verify =lista[1]
        public_verify = public_verify.encode()#Lo codifica para que este en bytes
        # hace lo mismo que el anterior
        firma_verify =lista[0]
        firma_verify = firma_verify.encode()

        #Se lee el archivo (mensaje) que el usuario quiere firmar, son de tipo pdf
        archivo = open("documento2.pdf", "rb")
        # lo lee y guarda en bytes en la variable contenido
        contenido = archivo.read()
        archivo.close()
        os.remove('documento2.pdf')
        os.remove('firma_y_clave.pem')

        #cargar base de datos
        base = pd.read_csv('data_base.csv')
        comprobar_caducidad(base,'data_base.csv')

        from binascii import unhexlify
        public_kv = unhexlify(public_verify)
        firma_kv = unhexlify(firma_verify)
        
        # la clave publica pasa de string a su formato original con 'verifyingkey.from_string'
        # se necesita especificar que curva se utilizó
        public_kv= VerifyingKey.from_string(public_kv, curve=ecdsa.NIST256p)
        #Se verifica la firma con la función 'verify'
        try:
            public_kv.verify(firma_kv, contenido, hashfunc=hashlib.sha256)
        except:
            resultado = 'La firma no se puede verficar' 
        else:
            resultado = 'La firma fue verificada con éxito'
    except: 
        resultado = 'Los archivos que introduciste no son los correctos.'
    return render_template("resultado.html", name=resultado)


nav.init_app(app)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
