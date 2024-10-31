import argparse
import time
import ifaddr
from scapy.all import sniff, conf, TCP, UDP, ICMP, IP, wrpcap
from rich.console import Console
from rich.table import Table
from rich import box
from threading import Thread, Event
import keyboard

console = Console()

protocol_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

stop_capture = Event()  # Evento para detener la captura
captured_packets = []  # Lista para almacenar paquetes capturados

def list_interfaces():
    console.print("[bold yellow]Interfaces de Red Disponibles:[/bold yellow]")
    interfaces = []

    adapters = ifaddr.get_adapters()
    scapy_interfaces = list(conf.ifaces.data.values())
    
    if not scapy_interfaces:
        console.print("[red]No se encontraron interfaces de red disponibles.[/red]")
        return interfaces

    for idx, iface in enumerate(scapy_interfaces):
        iface_name = iface.name
        friendly_name = None
        
        for adapter in adapters:
            if adapter.nice_name == iface_name or adapter.ips:
                friendly_name = adapter.nice_name
                break

        display_name = friendly_name if friendly_name else iface_name
        interfaces.append(iface_name)
        console.print(f"{idx + 1}. {display_name} ({iface_name})")
    
    return interfaces


def packet_callback(packet, show_in, show_out, target_ip, protocol_filter, ip_summary):
    if stop_capture.is_set():
        return  # Termina si se ha establecido el evento para detener la captura

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        proto = protocol_names.get(proto, "Desconocido")

        # Guarda el paquete capturado
        captured_packets.append(packet)  # Almacena el paquete en la lista global

        # Actualiza el resumen de IPs
        if src not in ip_summary:
            ip_summary[src] = {'sent': 0, 'received': 0, 'ports': set()}
        if dst not in ip_summary:
            ip_summary[dst] = {'sent': 0, 'received': 0, 'ports': set()}

        # Contar paquetes enviados y recibidos
        if show_in and dst == target_ip:
            ip_summary[dst]['received'] += 1
            ip_summary[src]['sent'] += 1
        elif show_out and src == target_ip:
            ip_summary[src]['sent'] += 1
            ip_summary[dst]['received'] += 1
        elif not show_in and not show_out:
            ip_summary[src]['sent'] += 1
            ip_summary[dst]['received'] += 1

        # Guardar puertos utilizados
        sport = packet.sport if TCP in packet or UDP in packet else "-"
        dport = packet.dport if TCP in packet or UDP in packet else "-"
        ip_summary[src]['ports'].add(sport)
        ip_summary[dst]['ports'].add(dport)

        if protocol_filter and not packet.haslayer(protocol_filter):
            return

        if target_ip and target_ip not in (src, dst):
            return

        # Imprimir información en tabla
        table = Table(box=box.SIMPLE)
        table.add_column("Origen", style="cyan")
        table.add_column("Destino", style="magenta")
        table.add_column("Protocolo", style="green")
        table.add_column("Puerto Origen", style="red")
        table.add_column("Puerto Destino", style="red")
        table.add_column("Tamaño", style="yellow")
        table.add_column("Info Adicional", style="blue")

        size = len(packet)
        info = ""

        if TCP in packet:
            flags = packet.sprintf("%TCP.flags%")
            info = f"Flags: {flags}"
        elif ICMP in packet:
            info = f"ICMP Type: {packet[ICMP].type}"

        table.add_row(src, dst, str(proto), str(sport), str(dport), str(size), info)
        console.print(table)


def summarize_ip_traffic(ip_summary):
    console.print("\n[bold green]Resumen de tráfico por IPs:[/bold green]")
    summary_table = Table(box=box.SIMPLE)
    summary_table.add_column("IP", style="cyan")
    summary_table.add_column("Paquetes Enviados", style="magenta")
    summary_table.add_column("Paquetes Recibidos", style="green")
    summary_table.add_column("Puertos Utilizados", style="yellow")

    for ip, data in ip_summary.items():
        summary_table.add_row(ip, str(data['sent']), str(data['received']), ', '.join(map(str, data['ports'])))
    
    console.print(summary_table)


def sniff_packets(interface, show_in, show_out, target_ip, protocol_filter, output_file, duration, promiscuous):
    console.print(f"[bold blue]Capturando tráfico en la interfaz: {interface}[/bold blue]")

    start_time = time.time()
    ip_summary = {}  # Resumen de tráfico por IP

    def capture_packet(packet):
        if stop_capture.is_set():  # Verifica si se debe detener la captura
            return False
        packet_callback(packet, show_in, show_out, target_ip, protocol_filter, ip_summary)
        
        # Terminar si se alcanza la duración máxima
        if duration and (time.time() - start_time) > duration:
            stop_capture.set()  # Detiene el hilo de captura al completar el tiempo

    sniff(iface=interface, prn=capture_packet, store=0, timeout=duration, promisc=promiscuous, stop_filter=lambda x: stop_capture.is_set())

    if output_file:
        wrpcap(output_file, captured_packets)  # Guarda la lista de paquetes capturados
        console.print(f"[green]Captura guardada en {output_file}[/green]")

    return ip_summary  # Retornar el resumen para su uso posterior


def main():
    parser = argparse.ArgumentParser(description="Programa mejorado de captura de tráfico de red en tiempo real.")
    parser.add_argument("-list", action="store_true", help="Muestra todas las interfaces de red y wifi disponibles.")
    parser.add_argument("-use", metavar="INTERFACE", help="Selecciona la interfaz de red para capturar el tráfico (número o nombre).")
    parser.add_argument("-only_in", action="store_true", help="Muestra sólo el tráfico de entrada.")
    parser.add_argument("-only_out", action="store_true", help="Muestra sólo el tráfico de salida.")
    parser.add_argument("-target", metavar="IP", help="Filtra tráfico relacionado con la IP especificada.")
    parser.add_argument("-protocol", metavar="PROTOCOLO", help="Filtra paquetes por protocolo (tcp, udp, icmp).")
    parser.add_argument("-pcap", metavar="FILE", help="Guarda los paquetes capturados en un archivo .pcap.")
    parser.add_argument("-duration", metavar="SECONDS", type=int, help="Tiempo máximo de captura en segundos.")
    parser.add_argument("-promiscuous", action="store_true", help="Habilita el modo promiscuo para capturar todos los paquetes en la red.")
    parser.add_argument("-help", action="store_true", help="Muestra todas las opciones del comando.")

    args = parser.parse_args()

    if args.help:
        parser.print_help()
    elif args.list:
        list_interfaces()
    elif args.use:
        interfaces = list_interfaces()
        
        try:
            interface_idx = int(args.use) - 1
            if interface_idx < 0 or interface_idx >= len(interfaces):
                console.print("[red]Número de interfaz no válido.[/red]")
                return
            interface = interfaces[interface_idx]
        except ValueError:
            interface = args.use
            if interface not in interfaces:
                console.print("[red]Nombre de interfaz no válido.[/red]")
                return

        show_in = args.only_in
        show_out = args.only_out
        target_ip = args.target
        output_file = args.pcap
        duration = args.duration
        promiscuous = args.promiscuous

        protocol_filter = None
        if args.protocol:
            protocol_filter = {
                'tcp': TCP,
                'udp': UDP,
                'icmp': ICMP
            }.get(args.protocol.lower())
            if not protocol_filter:
                console.print(f"[red]Protocolo '{args.protocol}' no reconocido.[/red]")
                return

        # Hilo para detectar la tecla "q" y detener la captura
        def check_exit_key():
            while not stop_capture.is_set():
                if keyboard.is_pressed('q'):
                    console.print("[red]Deteniendo la captura...[/red]")
                    stop_capture.set()
                    break

        exit_thread = Thread(target=check_exit_key)
        exit_thread.daemon = True
        exit_thread.start()

        ip_summary = sniff_packets(interface, show_in, show_out, target_ip, protocol_filter, output_file, duration, promiscuous)

        # Esperar a que el hilo de salida termine
        exit_thread.join()

        # Resumir tráfico IP
        summarize_ip_traffic(ip_summary)

    else:
        console.print("[red]Por favor, use '-help' para ver las opciones disponibles.[/red]")


if __name__ == "__main__":
    main()
