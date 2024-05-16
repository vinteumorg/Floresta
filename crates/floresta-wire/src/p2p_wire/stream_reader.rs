//! A simple async reader that reads data from a [Source] and builds a [Item] from it, assuming
//! item is [Decodable]. The main intent of this module is to read [RawNetworkMessages] from [TcpStream], because
//! we don't know how many bytes to read upfront, so we might read an incomplete message and try
//! to deserialize it, causing unrelated error. This module first reads the message reader
//! that has constant size (for RawNetworkMessage is 24). Then we look for payload size inside
//! this header. With payload size we can finally read the entire message and return a parsed
//! structure.

use std::marker::PhantomData;

use async_std::channel::Sender;
use async_std::io::ReadExt;
use bip324::PacketReader;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::deserialize_partial;
use bitcoin::consensus::Decodable;
use bitcoin::p2p::Magic;
use futures::AsyncRead;

use super::peer::PeerError;

/// A simple type that wraps a stream and returns T, if T is [Decodable].
pub struct StreamReader<Source: Sync + Send + ReadExt + Unpin + AsyncRead, Item: Decodable + Send> {
    /// Were we read bytes from, usually a TcpStream
    source: Source,
    /// Item is what we return, since we don't actually hold any concrete type, just use a
    /// phantom data to bind a type.
    phantom: PhantomData<Item>,
    /// Magic bits, we expect this at the beginning of all messages
    magic: Magic,
    /// Where should we send data
    sender: Sender<Result<Item, PeerError>>,
    /// Optional handling of encrypted V2 transport messages
    v2_decoder: Option<PacketReader>,
}
impl<Source, Item> StreamReader<Source, Item>
where
    Item: Decodable + Unpin + Send + 'static,
    Source: Sync + Send + ReadExt + Unpin + AsyncRead,
{
    /// Creates a new reader from a given stream
    pub fn new(
        stream: Source,
        magic: Magic,
        sender: Sender<Result<Item, PeerError>>,
        v2_decoder: Option<PacketReader>,
    ) -> Self {
        StreamReader {
            source: stream,
            phantom: PhantomData,
            magic,
            sender,
            v2_decoder,
        }
    }
    async fn read_loop_inner(&mut self) -> Result<(), PeerError> {
        if self.v2_decoder.is_some() {
            return self.read_v2().await;
        } else {
            return self.read_v1().await;
        }
    }
    async fn read_v1(&mut self) -> Result<(), PeerError> {
        loop {
            self.parse_v1_message().await?;
        }
    }

    async fn read_v2(&mut self) -> Result<(), PeerError> {
        loop {
            self.parse_v2_message().await?;
        }
    }

    async fn parse_v1_message(&mut self) -> Result<(), PeerError> {
        let mut data: Vec<u8> = vec![0; 24];

        // Read the reader first, so learn the payload size
        self.source.read_exact(&mut data).await?;
        let header: P2PMessageHeader = deserialize_partial(&data)?.0;
        if header.magic != self.magic {
            return Err(PeerError::MagicBitsMismatch);
        }
        // Network Message too big
        if header.length > (1024 * 1024 * 32) as u32 {
            return Err(PeerError::MessageTooBig);
        }

        data.resize(24 + header.length as usize, 0);
        // Read everything else
        self.source.read_exact(&mut data[24..]).await?;
        let message = deserialize(&data)?;
        let _ = self.sender.send(Ok(message)).await;
        Ok(())
    }

    async fn parse_v2_message(&mut self) -> Result<(), PeerError> {
        let decoder_ref = self
            .v2_decoder
            .as_mut()
            .ok_or(PeerError::V2DecryptionError)?;
        // the first 3 bytes of a v2 message encode the length
        let mut length_bytes = [0u8; 3];
        self.source.read_exact(&mut length_bytes);
        let contents_len = decoder_ref.decypt_len(length_bytes);
        let mut packet_bytes = vec![0u8; contents_len];
        // read the exact amount of bytes from the stream
        self.source.read_exact(&mut packet_bytes).await?;
        let contents = decoder_ref
            .decrypt_contents(packet_bytes, None)
            .map_err(|_| PeerError::V2DecryptionError)?
            .message;
        // peers may send decoy packages which may be safely ignored
        if let Some(content) = contents {
            // if the message content starts with zero bytes, the command string was encoded as 13 bytes
            if content.starts_with(&[0u8]) {
                let message = deserialize(&content[13..])?;
                let _ = self.sender.send(Ok(message)).await;
                return Ok(());
            } else {
                // otherwise the command string was short-hand encoded
                let message = deserialize(&content[1..])?;
                let _ = self.sender.send(Ok(message)).await;
                println!("succesful deser");
                return Ok(());
            }
        }
        // do nothing if the message was a decoy
        Ok(())
    }

    /// Tries to read from a parsed [Item] from [Source]. Only returns on error or if we have
    /// a valid Item to return
    pub async fn read_loop(mut self) {
        let value = self.read_loop_inner().await;
        if let Err(e) = value {
            let _ = self.sender.send(Err(e)).await;
        }
    }
}

#[derive(Debug)]
pub struct P2PMessageHeader {
    magic: Magic,
    _command: [u8; 12],
    length: u32,
    _checksum: u32,
}
impl Decodable for P2PMessageHeader {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let magic = Magic::consensus_decode(reader)?;
        let _command = <[u8; 12]>::consensus_decode(reader)?;
        let length = u32::consensus_decode(reader)?;
        let _checksum = u32::consensus_decode(reader)?;
        Ok(Self {
            _checksum,
            _command,
            length,
            magic,
        })
    }
}
