from scapy.all import rdpcap, ICMP
from termcolor import colored
import string

def extraer_mensaje(pcap_file):
    """
    Extrae el mensaje oculto en los paquetes ICMP.
    Toma el byte 8 del payload de cada paquete echo-request.
    """
    paquetes = rdpcap(pcap_file)
    mensaje_bytes = []

    for pkt in paquetes:
        if ICMP in pkt and pkt[ICMP].type == 8:  # echo-request
            raw = bytes(pkt[ICMP].payload)
            if len(raw) >= 9:
                mensaje_bytes.append(raw[8])  # byte 9 = índice 8

    return bytes(mensaje_bytes).decode("latin-1", errors="ignore")


def descifrar_cesar(texto):
    """
    Aplica todos los posibles corrimientos del cifrado César.
    Devuelve lista con (corrimiento, resultado).
    """
    resultados = []
    for shift in range(1, 26):
        descifrado = ""
        for c in texto:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                descifrado += chr((ord(c) - base - shift) % 26 + base)
            else:
                descifrado += c
        resultados.append((shift, descifrado))
    return resultados


def evaluar_opciones(opciones):
    """
    Devuelve la opción más probable usando múltiples criterios de evaluación.
    """
    def score(text):
        # Contar letras y espacios
        letras_espacios = sum(c in string.ascii_letters + " ñÑ" for c in text)
        
        # Bonus por palabras comunes en español
        palabras_comunes = ['el', 'la', 'de', 'que', 'y', 'a', 'en', 'un', 'es', 'se', 'no', 'te', 'lo', 'le', 'da', 'su', 'por', 'son', 'con', 'para', 'al', 'del', 'los', 'las', 'una', 'como', 'más', 'pero', 'sus', 'me', 'hasta', 'hay', 'donde', 'han', 'quien', 'están', 'estado', 'desde', 'todo', 'nos', 'durante', 'todos', 'uno', 'les', 'ni', 'contra', 'otros', 'ese', 'eso', 'ante', 'ellos', 'e', 'esto', 'mí', 'antes', 'algunos', 'qué', 'unos', 'yo', 'otro', 'otras', 'otra', 'él', 'tanto', 'esa', 'estos', 'mucho', 'quienes', 'nada', 'muchos', 'cual', 'poco', 'ella', 'estar', 'estas', 'algunas', 'algo', 'nosotros']
        
        palabras_texto = text.lower().split()
        palabras_encontradas = sum(1 for palabra in palabras_texto if palabra in palabras_comunes)
        
        # Penalizar caracteres extraños
        caracteres_raros = sum(1 for c in text if c not in string.ascii_letters + string.digits + " ñÑ.,!?¿¡()[]{}:;\"'")
        
        # Penalizar secuencias de caracteres repetidos
        repeticiones = sum(1 for i in range(len(text)-1) if text[i] == text[i+1] and text[i] not in "aeiou")
        
        # Calcular puntuación final
        puntuacion = letras_espacios + (palabras_encontradas * 3) - (caracteres_raros * 2) - (repeticiones * 1)
        
        return puntuacion

    return max(opciones, key=lambda x: score(x[1]))


if __name__ == "__main__":
    pcap_file = "CapturaFiltrados.pcapng"  # <--- cambia por tu archivo real
    mensaje_cifrado = extraer_mensaje(pcap_file)
    print(f"[+] Mensaje cifrado extraído: {mensaje_cifrado}")

    print("\n[+] Intentando descifrar con César:")
    opciones = descifrar_cesar(mensaje_cifrado)
    mejor = evaluar_opciones(opciones)

    print(f"\n[+] Mejor opción automática: Shift {mejor[0]} (puntuación: {evaluar_opciones([mejor])[1]})")
    print(colored(f"[✓] {mejor[1]}", "green"))
    
    print(f"\n[+] Todas las opciones:")
    for shift, texto in opciones:
        if shift == mejor[0]:
            print(colored(f"[✓] Shift {shift:2d}: {texto}", "green"))
        else:
            print(f"[ ] Shift {shift:2d}: {texto}")
    
    print(f"\n[+] Si sabes que el corrimiento correcto es 9:")
    texto_correcto = opciones[8][1]  # índice 8 = shift 9
    print(colored(f"[✓] Shift 9: {texto_correcto}", "yellow"))
