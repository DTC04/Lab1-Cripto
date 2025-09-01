# Laboratorio 1 - Criptografía y Seguridad en Redes

Este repositorio contiene tres scripts en Python desarrollados para simular un canal encubierto usando paquetes ICMP.

## Scripts

### 1. `Cifrado_Cesar.py`
Cifra o descifra un mensaje usando el algoritmo César con corrimiento configurable.

### 2. `Stealth.py`
Envía caracteres cifrados uno por uno dentro de paquetes ICMP, imitando el formato exacto de un ping normal (incluyendo padding y timestamp).

### 3. `mitm_decoder.py`
Captura paquetes ICMP desde un archivo `.pcapng` y descifra el mensaje usando fuerza bruta sobre el Cifrado César.

---

