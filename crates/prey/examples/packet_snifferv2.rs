use std::net::{SocketAddr, Ipv4Addr, SocketAddrV4};
use std::{io, thread};
use std::time::Duration;
use prey::buffer::BufferPool;

// Ajuste os caminhos de acordo com a sua árvore de módulos
use prey::network::{Connection, RawSocket};
use prey::packet::{Packet, EtherType, IpProtocol, Ipv4Header, Ipv6Header, TCPHeader, UDPHeader};

fn main() {
    let pool = BufferPool::new(10);

    // 1. Instanciamos o Raw Socket (precisa de sudo!)
    let raw_socket = match RawSocket::new() {
        Ok(s) => s,
        Err(e) => {
            println!("❌ Falha ao abrir Raw Socket. Você executou com sudo? Erro: {}", e);
            return;
        }
    };

    println!("🔥 Sniffer PREY rodando! Capturando pacotes Ethernet brutos...");
    println!("================================================================");

    let rx = pool.acquire().unwrap();
    let tx = pool.acquire().unwrap();

    // IP fictício apenas para preencher a struct atual
    let dummy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 0));

    // 2. Criamos a Connection passando o RawSocket
    let mut conn = Connection::new(raw_socket, dummy_addr, tx, rx).expect("Falha ao criar conexão.");

    let mut pacotes_lidos = 0;

    // 3. Loop infinito lendo a placa de rede
    loop {
        match conn.receive() {
            Ok(0) => {}
            Ok(n) => {
                pacotes_lidos += 1;
                let data = conn.read_buffer.data();

                println!("\n📦 Pacote #{} capturado ({} bytes originais)", pacotes_lidos, n);

                // Instanciando nosso canivete suíço (Zero-Copy!)
                let packet = Packet::new(data);

                // Dissecando a Camada 2 (Ethernet)
                match packet.ethernet_header() {
                    Ok(eth) => {
                        println!("  ↳ L2: {}", eth);

                        // Dissecando a Camada 3 (Rede) com base no EtherType
                        if let Ok(l3_data) = packet.payload_after_ethernet() {
                            let l4_protocol = match eth.ether_type {
                                EtherType::IPv4 => {
                                    if let Ok(ipv4) = Ipv4Header::parse(l3_data) {
                                        println!("  ↳ L3: {}", ipv4);
                                        ipv4.protocol
                                    } else {
                                        IpProtocol::Unknown(0)
                                    }
                                }
                                EtherType::IPv6 => {
                                    if let Ok(ipv6) = Ipv6Header::parse(l3_data) {
                                        println!("  ↳ L3: {}", ipv6);
                                        ipv6.next_header
                                    } else {
                                        IpProtocol::Unknown(0)
                                    }
                                }
                                _ => IpProtocol::Unknown(0),
                            };

                            // Poderíamos analisar L4 sequencialmente aqui também,
                            // mas vamos pular direto para testar o extrator automático!
                        }
                    }
                    Err(e) => println!("  ↳ Erro L2: {}", e),
                }

                // Testando a conversão em cadeia para pegar a mensagem real
                match packet.payload() {
                    Ok(payload) => {
                        if payload.is_empty() {
                            println!("  ↳ Payload: Vazio (Apenas cabeçalhos de controle)");
                        } else {
                            println!("  ↳ Payload: {} bytes de dados da aplicação L7 encontrados!", payload.len());

                            // Bônus: tenta imprimir o começo do payload como texto se for legível (ex: HTTP)
                            let snippet_len = std::cmp::min(payload.len(), 32);
                            let snippet = String::from_utf8_lossy(&payload[..snippet_len]);
                            println!("      Amostra: {:?}", snippet);
                        }
                    }
                    Err(e) => {
                        println!("  ↳ Erro na Extração L7: {}", e);
                    }
                }

                println!("----------------------------------------------------------------");

                // Limpamos o buffer para o próximo pacote
                conn.read_buffer.clear();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Nenhum pacote na placa nesse exato microssegundo
            }
            Err(e) => {
                println!("❌ Erro de leitura: {}", e);
                break;
            }
        }

        // Pausa rápida para não usar 100% da CPU
        thread::sleep(Duration::from_millis(1));
    }
}