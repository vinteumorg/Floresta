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
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message::RawNetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::Network;
use floresta_chain::UtreexoBlock;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

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
}

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

struct P2PMessageHeader {
    _magic: Magic,
    _command: [u8; 12],
    length: u32,
    _checksum: u32,
}

impl Decodable for P2PMessageHeader {
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

/// Create new read and write transports from existing reader and writer streams.
pub async fn new<R, W>(
    mut reader: R,
    mut writer: W,
    network: Network,
    allow_v1_fallback: bool,
) -> Result<(ReadTransport<R>, WriteTransport<W>), TransportError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + Sync,
{
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
            let (reader_protocol, writer_protocol) = protocol.into_split();
            Ok((
                ReadTransport::V2(reader, reader_protocol),
                WriteTransport::V2(writer, writer_protocol),
            ))
        }
        Err(e) => match e {
            ProtocolError::Io(_, ProtocolFailureSuggestion::RetryV1) if allow_v1_fallback => Ok((
                ReadTransport::V1(reader),
                WriteTransport::V1(writer, network),
            )),
            e => Err(TransportError::Protocol(e)),
        },
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
                if contents.first() == Some(&2) {
                    let block: UtreexoBlock = deserialize(&contents[1..])?;
                    Ok(UtreexoMessage::Block(block))
                } else {
                    // Standard message
                    let msg = deserialize_v2(contents)?;
                    Ok(UtreexoMessage::Standard(msg))
                }
            }
            ReadTransport::V1(reader) => {
                let mut data: Vec<u8> = vec![0; 24];
                reader.read_exact(&mut data).await?;

                let header: P2PMessageHeader = deserialize_partial(&data)?.0;
                data.resize(24 + header.length as usize, 0);
                reader.read_exact(&mut data[24..]).await?;

                if header._command[0..5] == [0x62, 0x6c, 0x6f, 0x63, 0x6b] {
                    let mut block_data = vec![0; header.length as usize];
                    block_data.copy_from_slice(&data[24..]);
                    let block: UtreexoBlock = deserialize(&block_data)?;
                    Ok(UtreexoMessage::Block(block))
                } else {
                    let msg: RawNetworkMessage = deserialize(&data)?;
                    Ok(UtreexoMessage::Standard(msg.payload().clone()))
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
