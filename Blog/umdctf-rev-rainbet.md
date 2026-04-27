**Flag:** `UMDCTF{one_might_argue_that_gambling_is_the_best_vice_but_they_would_be_wrong}`

**Categoría:** Rev

**Autor del Reto:** segal

***

## Contexto

Este reto estuvo súper entretenido de desarmar y me obligó a salir de mi zona de confort, dando pelea un buen rato con la lógica del juego.

A simple vista, era un sitio de apuestas online donde había que ganar 25 veces seguidas en dos juegos: un campo minado y uno de cruzar la calle. Imposible a pura suerte, así que había que buscarle la quinta pata al gato.

## Desafío: rainbet

> *"sponsored by rainbet (for legal reasons this is not true). their rng backend was leaked (for legal reasons this is also not true)! can you get enough max wins?"*

La interfaz nos daba acceso al casino online (`rainbet.challs.umdctf.io`). Para ayudarnos, nos pasaron dos archivos del backend: un script en Python (`rainbet.py`) y un binario compilado en WebAssembly (`rainbet_gen.wasm`).

El objetivo era simple: conseguir una racha (streak) de 25 victorias al hilo sin perder.

### ¿Qué hace exactamente el sistema?

El servidor usaba el archivo WASM para generar los tableros de juego. Al meter mano en el código, entendí que el generador de números aleatorios (RNG) no era verdaderamente aleatorio, sino determinista.

Se alimentaba del ID de nuestra sesión y del número de ronda actual. Es como si un crupier usara siempre la misma baraja en el mismo orden: si sabemos en qué mesa estamos y qué mano se está jugando, podemos predecir exactamente qué cartas van a salir.

Esto significaba que podíamos llamar al WASM localmente y ver dónde estaban las minas o los autos antes de que el servidor nos mandara el tablero oficial.

### Arquitectura y Estrategia: Armando el rompecabezas

Al intentar automatizar esto, me topé con un muro. El server no usaba peticiones HTTP normales, sino WebSockets (`wss://`). Además, cada movimiento que enviábamos tenía que ir firmado criptográficamente con un parámetro `sig`.

Tuve que trabajar harto mirando el código JavaScript del frontend. Resulta que la firma era un simple HMAC-SHA256. El servidor nos daba un `secret` en cada ronda, y el frontend generaba un hash combinando ese secreto con la jugada que queríamos hacer.

Como la lógica estaba expuesta en el lado del cliente y nosotros recibíamos el secreto, podíamos generar firmas válidas desde nuestro propio script y hacerle un bypass a la validación del server.

### Solución

Me demoré armando el entorno virtual en mi Kali para que `wasmtime` y `websocket-client` funcionaran bien juntos, pero era clave para correr el exploit de forma local.

Armé un script en Python que básicamente automatizaba todo el flujo: generaba el tablero localmente, calculaba los movimientos seguros, firmaba el payload y lo mandaba por WebSocket.

```python
# Resumen de la lógica principal del exploit
def play_round(ws, secret, sid, streak):
    # Generamos el juego localmente con el WASM filtrado
    game_info = rainbet.generate_game(sid, streak)
    
    if game_info["type"] == "mines":
        return play_mines(ws, secret, streak, game_info)
    elif game_info["type"] == "chicken":
        return play_chicken(ws, secret, streak, game_info)

# Bucle principal para ganar las 25 veces
while streak < 25:
    result = play_round(ws, secret, sid, streak)
    
    # El server nos rota el secret, lo actualizamos para la siguiente firma
    if "secret" in result: 
        secret = result["secret"]
    if "session_id" in result: 
        sid = result["session_id"]
```

### Ejecución y Flag obtenida

Dejé el script corriendo en mi terminal. Como ya sabíamos el futuro de cada tablero, el bot empezó a jugar de forma perfecta, esquivando minas y autos de manera automática.

Al llegar a la victoria 25, el servidor se rindió y nos escupió la flag por el socket.

```
[+] Conectado. ¡Empezando exploit!
[*] Racha 0/25 — Jugando: CHICKEN
[*] Racha 1/25 — Jugando: MINES
...
[*] Racha 24/25 — Jugando: MINES
[!!!] FLAG: UMDCTF{one_might_argue_that_gambling_is_the_best_vice_but_they_would_be_wrong}
```

***

## Resumen técnico de la vulnerabilidad

| Componente | Debilidad | Impacto |
|---|---|---|
| `rainbet_gen.wasm` | RNG determinista (seeded con `session_id + round_idx`) | Predicción total del tablero antes de jugar. |
| Firma `sig` | Lógica de firma HMAC expuesta en el frontend. | Permite forjar y firmar payloads válidos. |
| Protocolo WebSocket | Sin autenticación adicional por ronda. | Acceso programático sin restricciones. |

## Aprendizajes

* Esconder tu RNG en un binario WASM no sirve de absolutamente nada si lo alimentas con inputs predecibles. La seguridad por oscuridad nunca es buena idea en infra o desarrollo.
* Dejar la lógica de firma de datos en el cliente (frontend) es un regalo para cualquier atacante. Nos dejaron en bandeja cómo imitar el comportamiento del navegador.
* Estuvo rudo pelear con los WebSockets al principio, pero me sirvió muchísimo para entender cómo manipular tráfico no convencional en CTFs de web.
