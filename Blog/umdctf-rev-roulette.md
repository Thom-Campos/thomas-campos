**Flag:** `UMDCTF{I_R3ALLY-want-to-pl4y-the-p0werball,+but-my-d4d-said-no-so-im-b3tting-ill-win-on-POLYMARKETinstead}`

**Categoría:** Rev

**Autor del Reto:** NyxIsBad

***

## Contexto

Este reto de reversing me demoró bastante en resolver al principio. Un aplauso para NyxIsBad por armarlo, y a la vez un cariñoso "qué ganas de tirarte el PC por la cabeza" por llenarlo de trampas para volvernos locos.

Nos pasan el binario `roulette`. Pide apostar un número, si pones un 1 grita "JACKPOT", pero luego falla siempre. Un clásico bait.

## Reconocimiento inicial

Como siempre en infra, lo primero es entender qué tenemos en frente usando `file` y `checksec`.

Era un ELF de 64-bits estático y *stripped* (sin nombres de funciones para guiarnos). Lo bueno: no tenía protecciones de memoria (sin PIE ni canaries), ideal para meter breakpoints fijos.

Luego le tiré un `strace`. Vi que usaba `getrandom()`, o sea que los números eran cero predecibles, y confirmé que el "JACKPOT" del inicio era puro humo.

```
echo "1" | strace -e trace=read,write,getrandom ./roulette
```

## Entrando a picar: El ensamblador

Con `objdump` miré las entrañas del binario. Aquí di pelea porque el autor dejó un par de trucos pesados.

Primero, el programa validaba que el input midiera exactamente 106 bytes. Si ponías más o menos, te pateaba de una.

Segundo, el algoritmo real era un Stream Cipher de 27 vueltas. En cada ronda generaba una llave dinámica, le aplicaba XOR con un texto cifrado que tenía en memoria y comparaba los resultados.

## La solución: GDB al rescate

Hacer el reversing manual de toda esa matemática me iba a tomar la vida entera.

Cambié de estrategia. Como el binario hacía `input_correcto = keystream XOR ciphertext`, no necesitaba entender el algoritmo completo. Solo tenía que mirar la memoria en el momento exacto.

Armé un script con la API de Python para GDB. Básicamente, le hice un 'man-in-the-middle' al debugger. Primero, inyecté 106 letras "A" para pasar la validación inicial de longitud.

```bash
python3 -c "import sys; sys.stdout.write('A'*106)" > input.txt
```

Dejé que el script hiciera el trabajo sucio. En cada ronda, paraba justo en la instrucción XOR, leía la llave, calculaba el chunk correcto y sobrescribía nuestro input en vivo parcheando el registro `%edi`.

```python
class FlagDumper(gdb.Breakpoint):
    def stop(self):
        # Leemos la llave generada y el texto esperado desde memoria
        eax = int(gdb.parse_and_eval("$eax")) & 0xffffffff
        rcx = int(gdb.parse_and_eval("$rcx")) & 0xffffffffffffffff
        rbp = int(gdb.parse_and_eval("$rbp")) & 0xffffffffffffffff
        # Calculamos el input correcto y parcheamos en vivo
        gdb.execute(f"set $edi = {eax ^ c_val}")
        return False # Que siga corriendo
```

Al automatizar las 27 rondas, el programa creyó que le atinamos a la ruleta perfectamente y nos escupió la flag de salida.

## Aprendizajes

* Hay que darle mérito a NyxIsBad por ser un maldito genio malvado. Metió una cadena oculta en el binario diseñada exclusivamente como un prompt injection. Una jugada súper sucia, pero brillante.
* Confirmado: no siempre hay que cabecear revirtiendo toda la matemática. Usar el debugger dinámicamente para alterar valores en vuelo suele ser la ruta más inteligente.
