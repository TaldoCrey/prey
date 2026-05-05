//! # Packet module
//! The Packet module of PREY framework contains all the packet and stream interpreting information
//! that came from the stream or from the raw socket. It defines what is a packet and how to deal with
//! it.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

//To-do -> Checksums

/// # RawPacket
/// Struct that holds a pointer for the raw bytes of a packet in a buffer.
///
/// ### Lifetime <'a>
/// Used a lifetime so a raw packet pointing to a buffer lasts only while the buffer lasts too.
///
/// # Fields
/// - raw: `&'a [u8]` - Pointer to the raw bytes of the packet within a buffer.
pub struct Packet<'a> {
    pub raw: &'a [u8]
}

impl<'a> Packet<'a> {

    /// # fn new
    /// Function that creates a new Packet.
    ///
    /// # Params
    /// - raw: `&'a [u8]` - The raw bytes of the Packet.
    ///
    /// # Returns
    /// A new Packet Object.
    pub fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// # fn len
    /// Function that gets the total length of the packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// The total length of the packet.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// # fn is_empty
    /// Function that checks if a Packet is empty.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// **True** if the packet is empty, **False** if it's not.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// # fn ethernet_header
    /// Function that parses the packet to extract the **ethernet header**.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// A `Result` containing a *EthernetHeader* object or a static error message.
    pub fn ethernet_header(&self) -> Result<EthernetHeader, &'static str> {
        EthernetHeader::parse(self.raw)
    }

    /// # fn payload_after_ethernet
    /// Function that returns the payload after the ethernet header.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// A `Result` containing a **&'a \[u8]** slice of bytes or a static error message.
    pub fn payload_after_ethernet(&self) -> Result<&'a [u8], &'static str> {
        if self.raw.len() < 14 {
            return Err("No ethernet header.");
        }
        Ok(&self.raw[14..])
    }

    /// # fn payload
    /// Function that extract the payload of a Packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// A `Result` containing either a `&'a [u8]` reference for the slice of bytes within the buffer that
    /// represents the payload or either a static error message.
    pub fn payload(&self) -> Result<&'a [u8], &'static str> {
        let eth = EthernetHeader::parse(self.raw)?;
        let raw = self.payload_after_ethernet()?;
        let mut current_offset = 0;

        let protocol = match eth.ether_type {
            EtherType::IPv4 => {
                let ipv4 = Ipv4Header::parse(&raw[current_offset..])?;
                current_offset += ipv4.length as usize;
                ipv4.protocol
            },
            EtherType::IPv6 => {
                let ipv6 = Ipv6Header::parse(&raw[current_offset..])?;
                current_offset += 40;
                ipv6.next_header
            }
            _ => return Ok(&raw[current_offset..])
        };

        match protocol {
            IpProtocol::TCP => {
                let tcp = TCPHeader::parse(&raw[current_offset..])?;
                current_offset += tcp.data_offset as usize;
            },
            IpProtocol::UDP => {
                let udp = UDPHeader::parse(&raw[current_offset..])?;
                current_offset += 8;
            },
            _ => {}
        }

        if current_offset <= self.raw.len() {
            Ok(&raw[current_offset..])
        } else {
            Err("Packet have been compromised: Headers length surpass total packet length.")
        }
    }
}

/// # EtherType
/// Enum that contains the possible ethernet connection types.
/// # Types
/// - IPv4
/// - IPv6
/// - ARP
/// - Unknown - used for unmapped types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Unknown(u16)
}

impl From<u16> for EtherType {
    //Implementation of trait from to EtherType for initializing
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x86DD => EtherType::IPv6,
            0x0806 => EtherType::ARP,
            _ => EtherType::Unknown(value)
        }
    }
}

impl fmt::Display for EtherType {
    //Implementation of trait display to EtherType for displaying it on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::IPv4 => write!(f, "IPv4"),
            EtherType::IPv6 => write!(f, "IPv6"),
            EtherType::ARP => write!(f, "ARP"),
            EtherType::Unknown(val) => write!(f, "Unknown type: (0x{:04X})", val),
        }
    }
}

/// # EthernetHeader
/// Struct that contains all Ethernet Header information.
///
/// # Fields
/// - dst_mac: `[u8; 6]` - A array of 6 bytes that represents the Destination MAC address.
/// - src_mac: `[u8; 6]` - A array of 6 bytes that represents the Source MAC address.
/// - ether_type: `EtherType` - The ethernet connection type, mapped by the **EtherType enum**.
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: EtherType
}

impl EthernetHeader {
    /// # fn parse
    /// Extract the ethernet header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new EthernetHeader object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 14 {
            return Err("Packet is too short to have an Ethernet Header.");
        }

        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&raw[0..6]);

        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&raw[6..12]);

        let eth_type = EtherType::from(u16::from_be_bytes([raw[12], raw[13]]));

        Ok(Self {
            dst_mac,
            src_mac,
            ether_type: eth_type
        })
    }
}

impl fmt::Display for EthernetHeader {
    //Implementation of fmt::Display trait for EthernetHeader for better viewing.
    fn fmt(&self, f:&mut fmt::Formatter<'_>) -> fmt::Result {
        let dst = self.dst_mac;
        let dst_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);

        let src = self.src_mac;
        let src_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                              src[0], src[1], src[2], src[3], src[4], src[5]);

        write!(
            f,
            "Ethernet Header {{Destiny MAC: {}, Source MAC: {}, EthernetType: {} }}",
            dst_str, src_str, self.ether_type
        )
    }
}

/// # IpProtocol
/// Enum that contains the possible IP protocols types
///
/// # Types
/// - ICMP
/// - TCP
/// - UDP
/// - Unknown(u8) - used for unmapped protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    ICMP,
    TCP,
    UDP,
    Unknown(u8)
}

impl From<u8> for IpProtocol {
    //Implementation of trait from to IpProtocol for initializing
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::ICMP,
            6 => IpProtocol::TCP,
            17 => IpProtocol::UDP,
            _ => IpProtocol::Unknown(value)
        }
    }
}

impl fmt::Display for IpProtocol {
    //Implementation of trait display to EtherType for displaying it on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpProtocol::ICMP => write!(f, "ICMP"),
            IpProtocol::TCP => write!(f, "TCP"),
            IpProtocol::UDP => write!(f, "UDP"),
            IpProtocol::Unknown(val) => write!(f, "Unknown ({})", val),
        }
    }
}

/// # Ipv4Header
/// Struct containing all IPv4 Header information.
///
/// # Fields
/// - version: `u8` - A byte that represents the IP version.
/// - length: `u8` - A byte that represents the header length.
/// - total_length: `u8` - A half-word that represents the total length of the next layers of the packet.
/// - ttl: `u8` - A byte that represents the Packet's **Time-to-Live**.
/// - protocol: `IpProtocol` - The IP protocol of the packet, mapped by **IpProtocol enum**.
/// - src_ip: `Ipv4Addr` - The packet's source IP.
/// - dst_ip: `Ipv4Addr` - The packet's destination IP.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version: u8,
    pub length: u8,
    pub total_length: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr
}

impl Ipv4Header {
    /// # fn parse
    /// Extract the IPv4 header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new Ipv4Header object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 20 {
            return Err("Packet is too short to be IPv4.");
        }

        let version = raw[0] >> 4;
        let length = (raw[0] & 0x0F) * 4;

        if raw.len() < length as usize {
            return Err("Packet have been compromised.");
        }

        let total_length = u16::from_be_bytes([raw[2], raw[3]]);
        let ttl = raw[8];
        let protocol = IpProtocol::from(raw[9]);

        let src_ip = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
        let dst_ip = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);

        Ok( Self {
            version,
            length,
            total_length,
            ttl,
            protocol,
            src_ip,
            dst_ip
        } )
    }
}

impl fmt::Display for Ipv4Header {
    //Implementation of trait display to Ipv4Header for displaying it on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 {{ Source: {}, Destiny: {}, Protocol: {}, TTL: {}, Total Length: {} }}",
            self.src_ip, self.dst_ip, self.protocol, self.ttl, self.total_length
        )
    }
}

/// # Ipv6Header
/// Struct containing all IPv6 Header information.
///
/// # Fields
/// - version: `u8` - A byte that represents the IP version.
/// - payload_length: `u16` - A half-word that represents the total length of packet's next layers.
/// - next_header: `IpProtocol` - The IP protocol of the packet, mapped by **IpProtocol enum**.
/// - src_ip: `Ipv6Addr` - The packet's source IP.
/// - dst_ip: `Ipv6Addr` - The packet's destination IP.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Header {
    pub version: u8,
    pub payload_length: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr
}

impl Ipv6Header {
    /// # fn parse
    /// Extract the IPv6 header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new Ipv6Header object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 40 {
            return Err("Packet is too short to be IPv6.");
        }

        let version = raw[0] >> 4;
        let payload_length = u16::from_be_bytes([raw[4], raw[5]]);
        let next_header = IpProtocol::from(raw[6]);
        let hop_limit = raw[7];

        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&raw[8..24]);

        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&raw[24..40]);

        Ok(Self {
            version,
            payload_length,
            next_header,
            hop_limit,
            src_ip: Ipv6Addr::from(src_bytes),
            dst_ip: Ipv6Addr::from(dst_bytes)
        })
    }
}

impl fmt::Display for Ipv6Header {
    //Implementation of trait display to Ipv6Header for displaying it on screen.

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv6 {{ Source: {}, Destiny: {}, Hop Limit: {}, Payload Length: {}, Next Header: {} }}",
            self.src_ip, self.dst_ip, self.hop_limit, self.payload_length, self.next_header
        )
    }
}

/// # UDPHeader
/// Struct containing all UDP header information.
///
/// # Fields
/// - src_port: `u16` - A half-word that represents the packet's source port.
/// - dst_port: `u16` - A half-word that represents the packet's destination port.
/// - length: `u16` - A half-word that represents the header's length.
/// - checksum: `u16` - The header's **checksum** value.
#[derive(Debug, Clone, Copy)]
pub struct UDPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16
}

impl UDPHeader {
    /// # fn parse
    /// Extract the UDP header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new UDPHeader object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 8 {
            return Err("Packet is too short to be an UDP packet.");
        }

        Ok(Self {
            src_port: u16::from_be_bytes([raw[0], raw[1]]),
            dst_port: u16::from_be_bytes([raw[2], raw[3]]),
            length: u16::from_be_bytes([raw[4], raw[5]]),
            checksum: u16::from_be_bytes([raw[6], raw[7]])
        })
    }
}

impl fmt::Display for UDPHeader {
    //Implementation of trait display to UDPHeader for displaying it on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UDP {{ Source Port: {}, Destiny Port: {}, Length: {} bytes }}",
            self.src_port, self.dst_port, self.length
        )
    }
}

/// # TCPHeader
/// Struct containing all TCP header information.
///
/// # Fields
/// - src_port: `u16` - A half-word that represents the packet's source port.
/// - dst_port: `u16` - A half-word that represents the packet's destination port.
/// - seq_number: `u32` - A word that represents the packet's sequence number.
/// - ack_number: `u32` - A word that represents the packet's acknowledgement number.
/// - data_offset: `u8` - A byte that represents a offset to the start of packet's payload.
/// - flags: `u16` - A half-word that represents packet's flags.
/// - window_size: `u16` - A half-word that represents the sender's window size.
/// - checksum: `u16` - The header's **checksum** value.
/// - urgent_pointer: `u16` - A half-word that represents the end offset of urgent data.
#[derive(Debug, Clone, Copy)]
pub struct TCPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number:u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16
}

impl TCPHeader {
    /// # fn parse
    /// Extract the TCP header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new TCPHeader object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 20 {
            return Err("Packet is too short to be TCP.");
        }

        let data_offset = (raw[12] >> 4) * 4;

        if raw.len() < data_offset as usize {
            return Err("Packet have been compromised.");
        }

        let flags = ((raw[12] as u16 & 0x01) << 8) | (raw[13] as u16);

        Ok( Self{
            src_port: u16::from_be_bytes([raw[0], raw[1]]),
            dst_port: u16::from_be_bytes([raw[2], raw[3]]),
            seq_number: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            ack_number: u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
            data_offset,
            flags,
            window_size: u16::from_be_bytes([raw[14], raw[15]]),
            checksum: u16::from_be_bytes([raw[16], raw[17]]),
            urgent_pointer: u16::from_be_bytes([raw[18], raw[19]])
        } )
    }

    /// # fn is_syn
    /// Function that checks if it's a SYN packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated TCPHeader object of a packet.
    ///
    /// # Returns
    /// **True** if the flag `SYN` is active, **False** if it's not.
    pub fn is_syn(&self) -> bool {
        (self.flags & 0x02) != 0
    }

    /// # fn is_ack
    /// Function that checks if it's a ACK packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated TCPHeader object of a packet.
    ///
    /// # Returns
    /// **True** if the flag `ACK` is active, **False** if it's not.
    pub fn is_ack(&self) -> bool {
        (self.flags & 0x10) != 0
    }

    /// # fn is_fin
    /// Function that checks if it's a FIN packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated TCPHeader object of a packet.
    ///
    /// # Returns
    /// **True** if the flag `FIN` is active, **False** if it's not.
    pub fn is_fin(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// # fn is_rst
    /// Function that checks if it's a RST packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated TCPHeader object of a packet.
    ///
    /// # Returns
    /// **True** if the flag `RST` is active, **False** if it's not.
    pub fn is_rst(&self) -> bool {
        (self.flags & 0x04) != 0
    }
}

impl fmt::Display for TCPHeader {
    //Implementation of trait display to TCPHeader for displaying it on screen.

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let mut flags_str = String::new();

        if self.is_syn() { flags_str.push_str("SYN "); }
        if self.is_ack() { flags_str.push_str("ACK "); }
        if self.is_fin() { flags_str.push_str("FIN "); }
        if self.is_rst() { flags_str.push_str("RST "); }

        write!(
            f,
            "TCP {{ Source Port: {}, Destiny Port: {}, Seq Number: {}, Ack Number {}, Flags: [{}] }}",
            self.src_port, self.dst_port, self.seq_number, self.ack_number, flags_str
        )
    }
}