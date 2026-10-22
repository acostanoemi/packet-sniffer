#!/usr/bin/env python3
"""
Sniffer de paquetes - v4 (guardar y graficar)

Captura el trafico de TU red unos segundos, muestra un resumen y ademas:
  - guarda la captura en un archivo .pcap (se abre con Wireshark)
  - genera un grafico .png con el reparto por protocolo y los top servers

USO ETICO: corré esto SOLO en tu propia red / tu propia maquina.
Capturar trafico de redes ajenas es ilegal.

Necesita permisos de administrador:
    sudo python3 sniffer.py
"""

import os
import socket
from collections import Counter
from datetime import datetime

# matplotlib en modo "Agg": genera imagenes a archivo sin necesitar pantalla
# (importante porque corremos con sudo, donde puede no haber display).
os.environ.setdefault("MPLCONFIGDIR", "/tmp/mpl")   # evita warnings corriendo como root
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP

socket.setdefaulttimeout(1)

# --- Config: editá estos valores ---
SEGUNDOS = 15        # cuanto tiempo capturar. Cortás antes con Ctrl+C
INTERFAZ = None      # None = la placa por defecto. Ejemplos: "wlan0", "eth0"
# ------------------------------------

SERVICIOS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 3389: "RDP", 8080: "HTTP-alt",
}

# --- Acumuladores ---
total = 0
por_protocolo = Counter()
ips_privadas = Counter()
ips_publicas = Counter()
servicios_usados = Counter()
conexiones = set()


def es_privada(ip):
    if ip.startswith("192.168.") or ip.startswith("10."):
        return True
    if ip.startswith("172."):
        return 16 <= int(ip.split(".")[1]) <= 31
    return False


def puerto_de_servicio(sport, dport):
    """Devuelve el puerto del SERVICIO (el bajo/conocido), o None."""
    for p in (sport, dport):
        if p in SERVICIOS:
            return p
    for p in (sport, dport):
        if p < 1024:
            return p
    return None


def nombre_protocolo(paquete):
    if paquete.haslayer(TCP):
        return "TCP"
    if paquete.haslayer(UDP):
        return "UDP"
    if paquete.haslayer(ICMP):
        return "ICMP"
    return "OTRO"


def procesar(paquete):
    global total
    if not paquete.haslayer(IP):
        return

    total += 1
    por_protocolo[nombre_protocolo(paquete)] += 1

    origen, destino = paquete[IP].src, paquete[IP].dst
    for ip in (origen, destino):
        if es_privada(ip):
            ips_privadas[ip] += 1
        else:
            ips_publicas[ip] += 1

    sport = dport = None
    if paquete.haslayer(TCP):
        sport, dport = paquete[TCP].sport, paquete[TCP].dport
    elif paquete.haslayer(UDP):
        sport, dport = paquete[UDP].sport, paquete[UDP].dport

    if sport is not None:
        servicio = puerto_de_servicio(sport, dport)
        if servicio is not None:
            servicios_usados[servicio] += 1
        conexiones.add(frozenset({(origen, sport), (destino, dport)}))


def resolver(ip):
    """Reverse DNS: nombre de una IP, o la IP si no tiene."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def top_publicas_resueltas(n=5):
    """Top servers de internet, cada uno ya con su nombre resuelto."""
    return [(ip, resolver(ip), cuenta) for ip, cuenta in ips_publicas.most_common(n)]


def devolver_al_usuario(path):
    """
    Corremos con sudo, asi que los archivos quedan a nombre de root y despues
    no los podés borrar sin sudo. Se los devolvemos a tu usuario.
    """
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        os.chown(path, int(uid), int(gid))


def guardar_pcap(paquetes):
    nombre = datetime.now().strftime("captura_%Y%m%d_%H%M%S.pcap")
    wrpcap(nombre, paquetes)
    devolver_al_usuario(nombre)
    return nombre


def acortar(texto, largo=22):
    return texto if len(texto) <= largo else texto[:largo - 1] + "…"


def hacer_grafico(top_pub):
    if total == 0:
        return None

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Panel 1: torta de protocolos
    ax1.pie(
        list(por_protocolo.values()),
        labels=list(por_protocolo.keys()),
        autopct="%1.0f%%",
        startangle=90,
    )
    ax1.set_title("Paquetes por protocolo")

    # Panel 2: barras de top servers
    etiquetas = [acortar(nombre) for _, nombre, _ in top_pub]
    cuentas = [cuenta for _, _, cuenta in top_pub]
    ax2.barh(etiquetas, cuentas)
    ax2.invert_yaxis()                 # el mas grande arriba
    ax2.set_title("Top servers (paquetes)")
    ax2.set_xlabel("paquetes")

    plt.tight_layout()
    nombre = datetime.now().strftime("grafico_%Y%m%d_%H%M%S.png")
    plt.savefig(nombre, dpi=100)
    plt.close(fig)
    devolver_al_usuario(nombre)
    return nombre


def imprimir_resumen(top_pub, archivo_pcap):
    print("\n" + "=" * 40)
    print(f"RESUMEN ({SEGUNDOS} s)")
    print("=" * 40)
    print(f"\nPaquetes capturados: {total}")

    if total == 0:
        print("\nNo se capturo nada. Generá trafico mientras corre.")
        return

    print("\nPor protocolo:")
    for proto, cuenta in por_protocolo.most_common():
        print(f"  {proto:5} {cuenta}")

    print("\nDispositivos de tu red:")
    for ip, cuenta in ips_privadas.most_common(5):
        print(f"  {ip:16} {cuenta}")

    print("\nServers de internet:")
    for ip, nombre, cuenta in top_pub:
        print(f"  {ip:16} {cuenta:5}  {nombre}")

    print("\nServicios mas usados:")
    for puerto, cuenta in servicios_usados.most_common(5):
        print(f"  {puerto:5} {SERVICIOS.get(puerto, '?'):9} {cuenta}")

    print(f"\nConexiones distintas: {len(conexiones)}")
    print(f"\nGuardado: {archivo_pcap}  (abrilo con: wireshark {archivo_pcap})")


def main():
    print(f"Capturando {SEGUNDOS} segundos... (Ctrl+C para cortar antes)\n")
    print("Generá trafico: abrí una web o tirá 'ping google.com' en otra terminal.\n")

    # store=True: guardamos los paquetes en una lista para poder escribir el .pcap
    paquetes = sniff(iface=INTERFAZ, prn=procesar, timeout=SEGUNDOS, store=True)

    archivo_pcap = guardar_pcap(paquetes)
    top_pub = top_publicas_resueltas()   # resolvemos nombres una sola vez
    imprimir_resumen(top_pub, archivo_pcap)

    archivo_png = hacer_grafico(top_pub)
    if archivo_png:
        print(f"Grafico:  {archivo_png}  (abrilo con: xdg-open {archivo_png})")


if __name__ == "__main__":
    main()
