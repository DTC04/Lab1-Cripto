from scapy.all import IP, ICMP, send
import struct, time

def generar_payload(c):
    """
    Genera payload ICMP idéntico al de un ping real en Linux.
    - 8 bytes de timestamp (tiempo actual en segundos + microsegundos).
    - Secuencia de bytes 0x09..0x37 como en ping.
    - Primer byte del bloque reemplazado por el caracter del mensaje.
    """

    # Timestamp: segundos + microsegundos (8 bytes)
    ahora = time.time()
    segundos = int(ahora)
    microsegundos = int((ahora - segundos) * 1_000_000)
    ts_bytes = struct.pack("!II", segundos, microsegundos)  # 8 bytes

    # Relleno estándar de ping (resto del payload)
    padding = bytes(range(9, 56))  # 0x09..0x37 → 47 bytes
    payload = ts_bytes + padding

    # Reemplazar primer byte del padding con caracter secreto
    payload = payload[:8] + bytes(c, "utf-8") + payload[9:]
    return payload

def enviar_mensaje(destino, mensaje_cifrado):
    identificador = 0x148a  # igual que en tu captura
    print(f"[+] Enviando mensaje stealth a {destino}")

    for i, c in enumerate(mensaje_cifrado):
        payload = generar_payload(c)
        paquete = IP(dst=destino) / ICMP(id=identificador, seq=i) / payload
        send(paquete, verbose=0)
        print(f"[✓] Enviado caracter '{c}' en paquete ICMP seq={i}")

    # Último paquete con 'b'
    payload = generar_payload("b")
    paquete = IP(dst=destino) / ICMP(id=identificador, seq=len(mensaje_cifrado)) / payload
    send(paquete, verbose=0)
    print(f"[✓] Enviado caracter final 'b' en paquete ICMP seq={len(mensaje_cifrado)}")

if __name__ == "__main__":
    destino = "google.com"  # seguro para pruebas
    mensaje_cifrado = "larycxpajorj h bnpdarmjm nw anmnb y"
    enviar_mensaje(destino, mensaje_cifrado)
