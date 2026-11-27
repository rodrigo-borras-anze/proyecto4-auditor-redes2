export const SCAN_PRESETS = [
  {
    key: "top20",
    label: "Top 20 Puertos (TCP Stealth)",
    profile: "rapido",
    args: "-sS -n --top-ports 20 --max-retries 1 --host-timeout 15s -T4",
  },
  {
    key: "top50",
    label: "Top 50 Puertos (TCP Stealth)",
    profile: "rapido",
    args: "-sS -n --top-ports 50 --max-retries 1 --host-timeout 20s -T4",
  },
  {
    key: "servicios",
    label: "Servicios Abiertos y Versiones (-sV · Top 50)",
    profile: "normal",
    args: "-sS -sV --version-intensity 2 -n --top-ports 50 --max-retries 1 --host-timeout 25s -T4",
  },
  {
    key: "normal",
    label: "Normal (Top 50 + Servicios -sV + SO -O)",
    profile: "normal",
    args: "-sS -sV --version-intensity 2 -O --osscan-limit --max-os-tries 1 -n --top-ports 50 --max-retries 1 --host-timeout 25s -T4",
  },
  {
    key: "arp",
    label: "Descubrimiento ARP (Rápido LAN)",
    profile: "arp",
    args: "-sn -PR -n -T4",
  },
  {
    key: "icmp",
    label: "Descubrimiento ICMP (Ping)",
    profile: "icmp",
    args: "-sn -PE -n -T4",
  },
  {
    key: "tcp_discovery",
    label: "Descubrimiento TCP (SYN/ACK)",
    profile: "tcp_discovery",
    args: "-sn -PS22,80,443 -PA80,443 -n -T4",
  },
  {
    key: "udp",
    label: "Top 20 Puertos UDP (-sU)",
    profile: "udp",
    args: "-sU -n --top-ports 20 --max-retries 1 --host-timeout 25s -T4",
  },
  {
    key: "completo",
    label: "Auditoría Completa (NSE + Traceroute)",
    profile: "completo",
    args: "-sS -sV --version-intensity 2 -O --osscan-limit -n --top-ports 50 --script default --script-timeout 8s --host-timeout 35s --traceroute -T4",
  },
];