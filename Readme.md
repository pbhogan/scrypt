scrypt Estado de construcción
La función de derivación de claves scrypt está diseñada para ser mucho más segura contra ataques de fuerza bruta por hardware que funciones alternativas como PBKDF2 o bcrypt.

http://www.tarsnap.com/scrypt.html
http://github.com/pbhogan/scrypt
Por que deberías usar scrypt
Comparación de KDF

Los diseñadores de scrypt estiman que en hardware moderno (2009), si se gastan 5 segundos calculando una clave derivada, el costo de un ataque de fuerza bruta de hardware contra scrypt es aproximadamente 4000 veces mayor que el costo de un ataque similar contra bcrypt (para encontrar la misma contraseña), y 20000 veces mayor que un ataque similar contra PBKDF2.

Cómo instalar scrypt
gem install scrypt
Cómo usar scrypt
Funciona de manera bastante similar a ruby-bcrypt con algunas diferencias menores, especialmente en lo que respecta al factor de costo.

requiere  "scrypt"

# hash de la contraseña de un usuario 
contraseña  =  SCrypt :: Contraseña . create ( "mi gran secreto" ) 
# => "400 $ 8 $ 36 $ 78f4ae6983f76119 $ 37ec6ce55a2b928dc56ff9a7d0cdafbd7dbde49d9282c38a40b1434e88f24cf5"

# comparar con cadenas 
contraseña == "mi gran secreto"  # => 
contraseña verdadera == "una suposición insignificante"   # => falso
Password.create toma cinco opciones que determinarán la longitud de la clave y el tamaño de la sal, así como los límites de costo del cálculo:

:key_lenespecifica la longitud en bytes de la clave que desea generar. El valor predeterminado es 32 bytes (256 bits). El mínimo es 16 bytes (128 bits). El máximo es 512 bytes (4096 bits).
:salt_sizeespecifica el tamaño en bytes de la sal aleatoria que desea generar. El valor predeterminado y máximo es 32 bytes (256 bits). El mínimo es de 8 bytes (64 bits).
:max_time especifica el número máximo de segundos que debe tomar el cálculo.
:max_memespecifica el número máximo de bytes que debe tomar el cálculo. Un valor de 0 no especifica ningún límite superior. El mínimo es siempre 1 MB.
:max_memfracespecifica la memoria máxima en una fracción de los recursos disponibles para usar. Cualquier valor igual a 0 o mayor que 0.5 resultará en el uso de 0.5.
:costespecifica una cadena de costo (por ejemplo '400$8$19$') del calibratemétodo. Las :max_*opciones se ignorarán si se proporciona esta opción o si calibrate!se ha llamado.
Las opciones predeterminadas darán como resultado un tiempo de cálculo de aprox. 200 ms con 16 MB de uso de memoria.

Otras cosas que puedes hacer
requiere  "scrypt"

SCrypt :: Motor . calibrar 
# => "400 $ 8 $ 25 $"

salt  =  SCrypt :: Motor . generate_salt 
# => "400 $ 8 $ 26 $ b62e0f787a5fc373"

SCrypt :: Motor . hash_secret  "mi gran secreto" ,  salt 
# => "400 $ 8 $ 26 $ b62e0f787a5fc373 $ 0399ccd4fa26642d92741b17c366b7f6bd12ccea5214987af445d2bed97bc6a2"

SCrypt :: Motor . ¡calibrar! ( max_mem : 16 * 1024 * 1024 ) 
# => "4000 $ 8 $ 4 $"

SCrypt :: Motor . generate_salt 
# => "4000 $ 8 $ 4 $ c6d101522d3cb045"
Uso en rieles (y similares)
# almacenarlo de forma segura en el modelo de 
usuario usuario . update_attribute ( : contraseña ,  SCrypt :: Contraseña . create ( "mi gran secreto" ) )

# leerlo más tarde 
usuario . ¡recargar! 
contraseña  =  SCrypt :: Contraseña . new ( usuario . contraseña ) 
contraseña == "mi gran secreto"  # => verdadero
