def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        # Si es letra mayúscula
        if char.isupper():
            resultado += chr((ord(char) - 65 + corrimiento) % 26 + 65)
        # Si es letra minúscula
        elif char.islower():
            resultado += chr((ord(char) - 97 + corrimiento) % 26 + 97)
        # Si no es letra, lo deja igual
        else:
            resultado += char
    return resultado


# Programa principal
if __name__ == "__main__":
    texto = input("Ingrese el texto a cifrar: ")
    corrimiento = int(input("Ingrese el corrimiento (ej: 3): "))
    texto_cifrado = cifrado_cesar(texto, corrimiento)
    print("Texto cifrado:", texto_cifrado)
