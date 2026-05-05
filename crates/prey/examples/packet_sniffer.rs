use std::net::{SocketAddr, Ipv4Addr, SocketAddrV4};
use std::{io, thread};
use std::time::Duration;
use prey::buffer::{BufferPool, Buffer};


// Ajuste o caminho se o seu módulo raw estiver em outro lugar
use prey::network::{Connection, RawSocket};

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

    let rx = pool.acquire().unwrap();
    let tx = pool.acquire().unwrap();

    // IP fictício apenas para preencher a struct atual
    let dummy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 0));

    // 2. Criamos a Connection passando o RawSocket em vez do TcpStream
    let mut conn = Connection::new(raw_socket, dummy_addr, tx, rx).expect("Falha ao criar conexão.");

    let mut pacotes_lidos = 0;

    // 3. Loop infinito lendo a placa de rede
    loop {
        match conn.receive() {
            Ok(0) => {}
            Ok(n) => {
                pacotes_lidos += 1;
                let data = conn.read_buffer.data();

                // Vamos imprimir o tamanho e os primeiros 14 bytes (Cabeçalho Ethernet = MAC de Destino, MAC de Origem e Tipo)
                print!("📦 Pacote #{}: {} bytes capturados | Inicio (Hex): ", pacotes_lidos, n);
                for byte in data.iter().take(14) {
                    print!("{:02X} ", byte);
                }
                println!();

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

        // Pausa muito rápida para não usar 100% da CPU
        thread::sleep(Duration::from_millis(1));
    }
}