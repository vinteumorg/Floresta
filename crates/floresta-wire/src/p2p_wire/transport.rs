use std::io;

use bip324::serde::deserialize as deserialize_v2;
use bip324::serde::serialize as serialize_v2;
use bip324::AsyncProtocol;
use bip324::AsyncProtocolReader;
use bip324::AsyncProtocolWriter;
use bip324::ProtocolError;
use bip324::ProtocolFailureSuggestion;
use bip324::Role;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::deserialize_partial;
use bitcoin::consensus::serialize;
use bitcoin::consensus::Decodable;
use bitcoin::p2p::address::AddrV2;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message::RawNetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::Network;
use floresta_chain::UtreexoBlock;
use log::debug;
use log::info;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs;

use super::socks::Socks5Addr;
use super::socks::Socks5Error;
use super::socks::Socks5StreamBuilder;
use crate::address_man::LocalAddress;

type TcpReadTransport = ReadTransport<ReadHalf<TcpStream>>;
type TcpWriteTransport = WriteTransport<WriteHalf<TcpStream>>;
type TransportResult =
    Result<(TcpReadTransport, TcpWriteTransport, TransportProtocol), TransportError>;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("V2 protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("V2 serde error: {0}")]
    SerdeV2(#[from] bip324::serde::Error),
    #[error("V1 serde error: {0}")]
    SerdeV1(#[from] bitcoin::consensus::encode::Error),
    #[error("Proxy error: {0}")]
    Proxy(#[from] Socks5Error),
}

/// UTreeXO p2p message extensions to the base bitcoin protocol.
pub enum UtreexoMessage {
    Standard(NetworkMessage),
    Block(UtreexoBlock),
}

pub enum ReadTransport<R: AsyncRead + Unpin + Send> {
    V2(R, AsyncProtocolReader),
    V1(R),
}

pub enum WriteTransport<W: AsyncWrite + Unpin + Send + Sync> {
    V2(W, AsyncProtocolWriter),
    V1(W, Network),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Bitcoin nodes can communicate using different transport layer protocols.
pub enum TransportProtocol {
    /// Encrypted V2 protocol defined in BIP-324.
    V2,
    /// Original unencrypted V1 protocol.
    V1,
}

struct V1MessageHeader {
    _magic: Magic,
    _command: [u8; 12],
    length: u32,
    _checksum: u32,
}

impl Decodable for V1MessageHeader {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> std::result::Result<Self, bitcoin::consensus::encode::Error> {
        let _magic = Magic::consensus_decode(reader)?;
        let _command = <[u8; 12]>::consensus_decode(reader)?;
        let length = u32::consensus_decode(reader)?;
        let _checksum = u32::consensus_decode(reader)?;
        Ok(Self {
            _checksum,
            _command,
            length,
            _magic,
        })
    }
}

/// Establishes a TCP connection and negotiates the bitcoin protocol.
///
/// This function tries to connect to the specified address and negotiate the bitcoin protocol
/// with the remote node. It first attempts to use the V2 protocol, and if that fails with a specific
/// error suggesting fallback to V1 protocol (and `allow_v1_fallback` is true), it will retry
/// the connection with the V1 protocol.
///
/// # Arguments
///
/// * `address` - The address of a target node
/// * `network` - The bitcoin network
/// * `allow_v1_fallback` - Whether to allow fallback to V1 protocol if V2 negotiation fails
///
/// # Returns
///
/// Returns a tuple of read and write transports that can be used to communicate with the node.
///
/// # Errors
///
/// Returns a `TransportError` if the connection cannot be established or protocol negotiation fails.
pub async fn connect<A: ToSocketAddrs>(
    address: A,
    network: Network,
    allow_v1_fallback: bool,
) -> TransportResult {
    match try_connection(&address, network, false).await {
        Ok(transport) => Ok(transport),
        Err(TransportError::Protocol(ProtocolError::Io(_, ProtocolFailureSuggestion::RetryV1)))
            if allow_v1_fallback =>
        {
            try_connection(&address, network, true).await
        }
        Err(e) => Err(e),
    }
}

async fn try_connection<A: ToSocketAddrs>(
    address: &A,
    network: Network,
    force_v1: bool,
) -> TransportResult {
    let tcp_stream = TcpStream::connect(address).await?;
    tcp_stream.set_nodelay(true)?;
    let peer_addr = match tcp_stream.peer_addr() {
        Ok(addr) => addr.to_string(),
        Err(_) => String::from("unknown peer"),
    };
    let (mut reader, mut writer) = tokio::io::split(tcp_stream);

    match force_v1 {
        true => {
            info!("Using V1 protocol for connection to {}", peer_addr);
            Ok((
                ReadTransport::V1(reader),
                WriteTransport::V1(writer, network),
                TransportProtocol::V1,
            ))
        }
        false => match AsyncProtocol::new(
            network,
            Role::Initiator,
            None,
            None,
            &mut reader,
            &mut writer,
        )
        .await
        {
            Ok(protocol) => {
                info!(
                    "Successfully established V2 protocol connection to {}",
                    peer_addr
                );
                let (reader_protocol, writer_protocol) = protocol.into_split();
                Ok((
                    ReadTransport::V2(reader, reader_protocol),
                    WriteTransport::V2(writer, writer_protocol),
                    TransportProtocol::V2,
                ))
            }
            Err(e) => {
                debug!(
                    "Failed to establish V2 protocol connection to {}: {:?}",
                    peer_addr, e
                );
                Err(TransportError::Protocol(e))
            }
        },
    }
}

/// Establishes a connection through a SOCKS5 proxy and negotiates the bitcoin protocol.
///
/// This function connects to a SOCKS5 proxy, establishes a connection to the target address
/// through the proxy, and then negotiates the bitcoin protocol. Like `connect`, it first tries
/// the V2 protocol and can fall back to V1 if needed and allowed.
///
/// # Arguments
///
/// * `proxy_addr` - The address of the SOCKS5 proxy
/// * `address` - The target address to connect to through the proxy
/// * `port` - The port to connect to on the target
/// * `network` - The bitcoin network
/// * `allow_v1_fallback` - Whether to allow fallback to V1 protocol if V2 negotiation fails
///
/// # Returns
///
/// Returns a tuple of read and write transports that can be used to communicate with the node.
///
/// # Errors
///
/// Returns a `TransportError` if the proxy connection cannot be established, the connection
/// to the target fails, or protocol negotiation fails.
pub async fn connect_proxy<A: ToSocketAddrs>(
    proxy_addr: A,
    address: LocalAddress,
    network: Network,
    allow_v1_fallback: bool,
) -> TransportResult {
    let addr = match address.get_address() {
        AddrV2::Cjdns(addr) => Socks5Addr::Ipv6(addr),
        AddrV2::I2p(addr) => Socks5Addr::Domain(addr.into()),
        AddrV2::Ipv4(addr) => Socks5Addr::Ipv4(addr),
        AddrV2::Ipv6(addr) => Socks5Addr::Ipv6(addr),
        AddrV2::TorV2(addr) => Socks5Addr::Domain(addr.into()),
        AddrV2::TorV3(addr) => Socks5Addr::Domain(addr.into()),
        AddrV2::Unknown(_, _) => {
            return Err(TransportError::Proxy(Socks5Error::InvalidAddress));
        }
    };

    match try_proxy_connection(&proxy_addr, &addr, address.get_port(), network, false).await {
        Ok(transport) => Ok(transport),
        Err(TransportError::Protocol(ProtocolError::Io(_, ProtocolFailureSuggestion::RetryV1)))
            if allow_v1_fallback =>
        {
            try_proxy_connection(&proxy_addr, &addr, address.get_port(), network, true).await
        }
        Err(e) => Err(e),
    }
}

async fn try_proxy_connection<A: ToSocketAddrs>(
    proxy_addr: A,
    target_addr: &Socks5Addr,
    port: u16,
    network: Network,
    force_v1: bool,
) -> TransportResult {
    let proxy = TcpStream::connect(proxy_addr).await?;
    let stream = Socks5StreamBuilder::connect(proxy, target_addr, port).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);

    match force_v1 {
        true => {
            info!(
                "Using V1 protocol for proxy connection to {:?}",
                target_addr
            );
            Ok((
                ReadTransport::V1(reader),
                WriteTransport::V1(writer, network),
                TransportProtocol::V1,
            ))
        }
        false => {
            match AsyncProtocol::new(
                network,
                Role::Initiator,
                None,
                None,
                &mut reader,
                &mut writer,
            )
            .await
            {
                Ok(protocol) => {
                    info!(
                        "Successfully established V2 protocol proxy connection to {:?}",
                        target_addr
                    );
                    let (reader_protocol, writer_protocol) = protocol.into_split();
                    Ok((
                        ReadTransport::V2(reader, reader_protocol),
                        WriteTransport::V2(writer, writer_protocol),
                        TransportProtocol::V2,
                    ))
                }
                Err(e) => {
                    debug!(
                        "Failed to establish V2 protocol proxy connection to {:?}: {:?}",
                        target_addr, e
                    );
                    Err(TransportError::Protocol(e))
                }
            }
        }
    }
}

impl<R> ReadTransport<R>
where
    R: AsyncRead + Unpin + Send,
{
    /// Read the next message from the transport.
    pub async fn read_message(&mut self) -> Result<UtreexoMessage, TransportError> {
        match self {
            ReadTransport::V2(reader, protocol) => {
                let payload = protocol.read_and_decrypt(reader).await?;
                let contents = payload.contents();

                // Check if it's a block message by looking at the short ID.
                match contents.first() {
                    Some(&2) => {
                        let block: UtreexoBlock = deserialize(&contents[1..])?;
                        Ok(UtreexoMessage::Block(block))
                    }
                    _ => {
                        // Standard message
                        let msg = deserialize_v2(contents)?;
                        Ok(UtreexoMessage::Standard(msg))
                    }
                }
            }
            ReadTransport::V1(reader) => {
                let mut data: Vec<u8> = vec![0; 24];
                reader.read_exact(&mut data).await?;

                let header: V1MessageHeader = deserialize_partial(&data)?.0;
                data.resize(24 + header.length as usize, 0);
                reader.read_exact(&mut data[24..]).await?;

                match header._command[0..5] {
                    [0x62, 0x6c, 0x6f, 0x63, 0x6b] => {
                        let mut block_data = vec![0; header.length as usize];
                        block_data.copy_from_slice(&data[24..]);
                        let block: UtreexoBlock = deserialize(&block_data)?;
                        Ok(UtreexoMessage::Block(block))
                    }
                    _ => {
                        let msg: RawNetworkMessage = deserialize(&data)?;
                        Ok(UtreexoMessage::Standard(msg.payload().clone()))
                    }
                }
            }
        }
    }
}

impl<W> WriteTransport<W>
where
    W: AsyncWrite + Unpin + Send + Sync,
{
    /// Write a message to the transport.
    pub async fn write_message(&mut self, message: NetworkMessage) -> Result<(), TransportError> {
        match self {
            WriteTransport::V2(writer, protocol) => {
                let data = serialize_v2(message)?;
                protocol.encrypt_and_write(&data, writer).await?;
            }
            WriteTransport::V1(writer, network) => {
                let data = &mut RawNetworkMessage::new(network.magic(), message);
                let data = serialize(&data);
                writer.write_all(&data).await?;
                writer.flush().await?;
            }
        }
        Ok(())
    }

    /// Shutdown the transport.
    pub async fn shutdown(&mut self) -> Result<(), TransportError> {
        match self {
            WriteTransport::V2(writer, _) => {
                writer.shutdown().await?;
            }
            WriteTransport::V1(writer, _) => {
                writer.shutdown().await?;
            }
        }
        Ok(())
    }
}
