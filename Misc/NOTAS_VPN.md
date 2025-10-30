cd /home/kali/Desktop/RT

aluno5-tecnico
Bgh@nyNj0!
aluno5@tecnicomais.vpn

aluno15-tecnico
&2CmEfgd6S
aluno15@tecnicomais.vpn

https://ciberium.cybers3c.pt

┌──(root㉿kali-mrib)-[/home/kali/Downloads]
└─# openvpn sslvpn-aluno5-tecnico-client-config.ovpn 
2025-10-27 18:20:42 Note: Kernel support for ovpn-dco missing, disabling data channel offload.
2025-10-27 18:20:42 OpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
2025-10-27 18:20:42 library versions: OpenSSL 3.5.3 16 Sep 2025, LZO 2.10
2025-10-27 18:20:42 DCO version: N/A
Enter Auth Username: aluno5-tecnico
Enter Auth Password: ••••••••••              
2025-10-27 18:21:06 TCP/UDP: Preserving recently used remote address: [AF_INET]65.21.239.46:8443
2025-10-27 18:21:06 Socket Buffers: R=[131072->131072] S=[16384->16384]
2025-10-27 18:21:06 Attempting to establish TCP connection with [AF_INET]65.21.239.46:8443
2025-10-27 18:21:06 TCP connection established with [AF_INET]65.21.239.46:8443
2025-10-27 18:21:06 TCPv4_CLIENT link local: (not bound)
2025-10-27 18:21:06 TCPv4_CLIENT link remote: [AF_INET]65.21.239.46:8443
2025-10-27 18:21:06 TLS: Initial packet from [AF_INET]65.21.239.46:8443, sid=662cf0a2 402d96c6
2025-10-27 18:21:06 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
2025-10-27 18:21:06 VERIFY OK: depth=2, C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
2025-10-27 18:21:06 VERIFY OK: depth=1, C=US, O=DigiCert Inc, OU=www.digicert.com, CN=RapidSSL TLS RSA CA G1
2025-10-27 18:21:06 VERIFY X509NAME OK: CN=ciberium.cybers3c.pt
2025-10-27 18:21:06 VERIFY OK: depth=0, CN=ciberium.cybers3c.pt
2025-10-27 18:21:06 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_CHACHA20_POLY1305_SHA256, peer certificate: 4096 bits RSA, signature: RSA-SHA256, peer temporary key: 253 bits X25519
2025-10-27 18:21:06 [ciberium.cybers3c.pt] Peer Connection Initiated with [AF_INET]65.21.239.46:8443
2025-10-27 18:21:06 TLS: move_session: dest=TM_ACTIVE src=TM_INITIAL reinit_src=1
2025-10-27 18:21:06 TLS: tls_multi_process: initial untrusted session promoted to trusted
2025-10-27 18:21:07 SENT CONTROL [ciberium.cybers3c.pt]: 'PUSH_REQUEST' (status=1)
2025-10-27 18:21:08 PUSH: Received control message: 'PUSH_REPLY,route-gateway 172.17.0.1,sndbuf 0,rcvbuf 0,ping 450,ping-restart 1800,route 10.0.5.0 255.255.255.0,topology subnet,route remote_host 255.255.255.255 net_gateway,inactive 7200 61440,ifconfig 172.17.0.2 255.255.240.0,peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm,tun-mtu 1500'
2025-10-27 18:21:08 OPTIONS IMPORT: --sndbuf/--rcvbuf options modified
2025-10-27 18:21:08 Socket Buffers: R=[131072->131072] S=[87040->87040]
2025-10-27 18:21:08 OPTIONS IMPORT: --ifconfig/up options modified
2025-10-27 18:21:08 OPTIONS IMPORT: route options modified
2025-10-27 18:21:08 OPTIONS IMPORT: route-related options modified
2025-10-27 18:21:08 OPTIONS IMPORT: tun-mtu set to 1500
2025-10-27 18:21:08 net_route_v4_best_gw query: dst 0.0.0.0
2025-10-27 18:21:08 net_route_v4_best_gw result: via 10.0.2.2 dev eth0
2025-10-27 18:21:08 ROUTE_GATEWAY 10.0.2.2/255.255.255.0 IFACE=eth0 HWADDR=08:00:27:d1:f8:5d
2025-10-27 18:21:08 TUN/TAP device tun0 opened
2025-10-27 18:21:08 net_iface_mtu_set: mtu 1500 for tun0
2025-10-27 18:21:08 net_iface_up: set tun0 up
2025-10-27 18:21:08 net_addr_v4_add: 172.17.0.2/20 dev tun0
2025-10-27 18:21:08 net_route_v4_add: 65.21.239.46/32 via 10.0.2.2 dev [NULL] table 0 metric -1
2025-10-27 18:21:08 net_route_v4_add: 10.0.5.0/24 via 172.17.0.1 dev [NULL] table 0 metric -1
2025-10-27 18:21:08 net_route_v4_add: 65.21.239.46/32 via 10.0.2.2 dev [NULL] table 0 metric -1
2025-10-27 18:21:08 sitnl_send: rtnl: generic error (-17): File exists
2025-10-27 18:21:08 NOTE: Linux route add command failed because route exists
2025-10-27 18:21:08 Initialization Sequence Completed
2025-10-27 18:21:08 Data Channel: cipher 'AES-256-GCM', peer-id: 0
2025-10-27 18:21:08 Timers: ping 450, ping-restart 1800, inactive 7200 61440
2025-10-27 18:21:08 Protocol options: protocol-flags cc-exit tls-ekm






# *** FLAGS TCP ***
# SYN = inicia conexão (0x02)
# ACK = reconhecimento (0x10)
# RST = reset (abort) (0x04)
# FIN = fim de envio (0x01)
# PSH = push (dados imediatos) (0x08)
# URG = urgente (0x20)
# ECE = Explicit Congestion (0x40)
# CWR = Congestion Window Reduced (0x80)
# Comuns combinados:
# SYN (0x02)
# SYN,ACK (0x12)
# RST,ACK (0x14)
# FIN,ACK (0x11)
# ACK só (0x10) — pacote normal de dados/ack.
# *** ESTADOS TCP ***
# CLOSED — sem socket
# LISTEN — servidor espera SYN
# SYN-SENT — cliente enviou SYN, espera SYN/ACK
# SYN-RECEIVED — recebeu SYN, respondeu SYN/ACK, espera ACK
# ESTABLISHED — conexão aberta, troca de dados
# FIN-WAIT-1 — iniciou fechamento (envia FIN)
# FIN-WAIT-2 — aguardando FIN remoto
# CLOSING — ambos fecharam quase simultâneo
# TIME-WAIT — espera para garantir fim seguro (2×MSL)
# CLOSE-WAIT — recebeu FIN, esperando app fechar
# LAST-ACK — enviou FIN, espera ACK final





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


