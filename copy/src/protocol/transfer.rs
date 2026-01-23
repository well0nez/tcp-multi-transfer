//! Transfer Protocol Messages
//!
//! Binary protocol for efficient file transfer between peers

use bytes::{Buf, BufMut, Bytes, BytesMut};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Hello = 1,
    FileInfo = 2,
    FileInfoAck = 3,
    Data = 4,
    Done = 5,
    Ack = 6,
    StreamInfo = 8,
    StreamInfoAck = 9,
    ChunkAck = 10,
    ChunkHeader = 13,
    ChunkNack = 15,
    TransferDone = 16,
    TransferDoneAck = 17,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Hello),
            2 => Some(Self::FileInfo),
            3 => Some(Self::FileInfoAck),
            4 => Some(Self::Data),
            5 => Some(Self::Done),
            6 => Some(Self::Ack),
            8 => Some(Self::StreamInfo),
            9 => Some(Self::StreamInfoAck),
            10 => Some(Self::ChunkAck),
            13 => Some(Self::ChunkHeader),
            15 => Some(Self::ChunkNack),
            16 => Some(Self::TransferDone),
            17 => Some(Self::TransferDoneAck),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HelloMessage {
    pub role: String,
}

impl HelloMessage {
    pub fn encode(&self) -> BytesMut {
        let role_bytes = self.role.as_bytes();
        let mut buf = BytesMut::with_capacity(5 + role_bytes.len());
        buf.put_u8(MessageType::Hello as u8);
        buf.put_u32(role_bytes.len() as u32);
        buf.put_slice(role_bytes);
        buf
    }
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 5 { return None; }
        let mut cursor = &data[1..];
        let len = cursor.get_u32() as usize;
        if data.len() < 5 + len { return None; }
        let role = String::from_utf8(data[5..5+len].to_vec()).ok()?;
        Some(Self { role })
    }
}

#[derive(Debug, Clone)]
pub struct StreamInfoMessage {
    pub stream_index: u32,
    pub total_streams: u32,
}

impl StreamInfoMessage {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(9);
        buf.put_u8(MessageType::StreamInfo as u8);
        buf.put_u32(self.stream_index);
        buf.put_u32(self.total_streams);
        buf
    }
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 9 { return None; }
        let mut cursor = &data[1..];
        let stream_index = cursor.get_u32();
        let total_streams = cursor.get_u32();
        Some(Self { stream_index, total_streams })
    }
}

#[derive(Debug, Clone)]
pub struct ChunkAckMessage {
    pub chunk_id: u32,
    pub is_nack: bool,
}

impl ChunkAckMessage {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(5);
        let msg_type = if self.is_nack { MessageType::ChunkNack } else { MessageType::ChunkAck };
        buf.put_u8(msg_type as u8);
        buf.put_u32(self.chunk_id);
        buf
    }
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 5 { return None; }
        let msg_type = MessageType::from_u8(data[0])?;
        if msg_type != MessageType::ChunkAck && msg_type != MessageType::ChunkNack { return None; }
        let mut cursor = &data[1..];
        let chunk_id = cursor.get_u32();
        Some(Self { chunk_id, is_nack: msg_type == MessageType::ChunkNack })
    }
}

#[derive(Debug, Clone)]
pub struct ChunkHeaderMessage {
    pub chunk_id: u32,
    pub offset: u64,
    pub len: u32,
    pub hash32: u32,
}

impl ChunkHeaderMessage {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(21);
        buf.put_u8(MessageType::ChunkHeader as u8);
        buf.put_u32(self.chunk_id);
        buf.put_u64(self.offset);
        buf.put_u32(self.len);
        buf.put_u32(self.hash32);
        buf
    }
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 21 { return None; }
        let mut cursor = &data[1..];
        let chunk_id = cursor.get_u32();
        let offset = cursor.get_u64();
        let len = cursor.get_u32();
        let hash32 = cursor.get_u32();
        Some(Self { chunk_id, offset, len, hash32 })
    }
}

#[derive(Debug, Clone)]
pub struct FileInfoMessage {
    pub filename: String,
    pub file_size: u64,
    pub sha256: [u8; 32],
}

impl FileInfoMessage {
    pub fn encode(&self) -> BytesMut {
        let name_bytes = self.filename.as_bytes();
        let mut buf = BytesMut::with_capacity(45 + name_bytes.len());
        buf.put_u8(MessageType::FileInfo as u8);
        buf.put_u32(name_bytes.len() as u32);
        buf.put_u64(self.file_size);
        buf.put_slice(name_bytes);
        buf.put_slice(&self.sha256);
        buf
    }
    #[allow(dead_code)]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 13 { return None; }
        let mut cursor = &data[1..];
        let name_len = cursor.get_u32() as usize;
        let file_size = cursor.get_u64();
        if data.len() < 13 + name_len + 32 { return None; }
        let filename = String::from_utf8(data[13..13+name_len].to_vec()).ok()?;
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&data[13+name_len..13+name_len+32]);
        Some(Self { filename, file_size, sha256 })
    }
}

pub fn encode_simple(msg_type: MessageType) -> Bytes {
    Bytes::from(vec![msg_type as u8])
}