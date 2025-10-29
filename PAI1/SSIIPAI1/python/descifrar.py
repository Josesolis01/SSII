def rot47(texto):
    res = []
    for c in texto:
        o = ord(c)
        if 33 <= o <= 126:  # rango de ROT47
            res.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            res.append(c)
    return "".join(res)

def desplazar_ascii(texto, desplazamiento=+1):
    res = []
    for c in texto:
        o = ord(c)
        res.append(chr((o + desplazamiento) % 127))
    return "".join(res)

def decodificar(texto):
    paso1 = rot47(texto)                # primero ROT47
    paso2 = desplazar_ascii(paso1, +1)  # luego desplazamiento -1
    return paso2


# === Ejemplo de uso ===
cifrado = "z1 C97E95>D5 9>6?B=139?> 5C _^^S 3?>6945>391<\ $5 1IE41B1 1 @B?C57E9B 5> <1 9>F5CD97139?>\ |? D5 3?>695CZ >? D?4?C <?C B5D?C AE5 D5>5=?C @5>C14?C C?> D1> C5>39<<?C 3?=? 5CD1 B?D139?> 45 31B13D5B5C\ t9B=14?h %> 1>D97E? 1<E=>?" 
print(decodificar(cifrado))
