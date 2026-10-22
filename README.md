# packet-sniffer

Sniffer de paquetes educativo, hecho con Python y scapy. Captura el tráfico de la red, lo analiza y arma un resumen con estadísticas, guarda la captura para Wireshark y genera un gráfico.

Proyecto de aprendizaje para entender cómo funciona TCP/IP viéndolo pasar de verdad.

## ⚠️ Uso ético y legal

Esta herramienta captura TODO el tráfico que pasa por la placa de red, incluido el que no es tuyo. Usala **solo en tu propia red o tu propia máquina**.

Capturar tráfico de redes ajenas (la facu, el trabajo, un café, la red de un vecino) es ilegal en Argentina y en casi todo el mundo, por más que sea "para aprender". No lo hagas.

## Qué hace

- Captura el tráfico durante unos segundos
- Resume por protocolo (TCP / UDP / ICMP)
- Separa los dispositivos de tu red de los servers de internet
- Resuelve el nombre de cada server (reverse DNS)
- Detecta los servicios usados (HTTPS, DNS, etc.) ignorando los puertos efímeros
- Cuenta las conexiones distintas
- Guarda la captura en `.pcap` para abrir en Wireshark
- Genera un gráfico `.png` (protocolos y top servers)

## Requisitos

- Python 3
- scapy y matplotlib

En Ubuntu / Debian, lo más simple (porque el sniffer corre con sudo):

```bash
sudo apt install python3-scapy python3-matplotlib
```

## Uso

```bash
sudo python3 sniffer.py
```

Captura 15 segundos y muestra el resumen. Para cambiar la duración o elegir una placa, editá `SEGUNDOS` e `INTERFAZ` arriba de todo en `sniffer.py`.

Mientras corre, generá tráfico: abrí una web o tirá un `ping` desde otra terminal.

Cada corrida deja dos archivos en la carpeta: `captura_FECHA.pcap` y `grafico_FECHA.png`. Las capturas están en `.gitignore` para no subir tráfico real al repo.

## Roadmap

- [x] v1: capturar y mostrar paquetes
- [x] v2: contar y analizar (por protocolo, top de IPs, conexiones)
- [x] v3: resolver nombres de servers y limpiar los puertos efímeros
- [x] v4: guardar a `.pcap` y generar gráfico
- [ ] v5: ideas sueltas — filtrar por protocolo, alertar tráfico sin cifrar, detectar escaneos
