use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum MsgType {
    Checkin = 1,
    Beacon = 2,
    Result = 3,
}

impl Serialize for MsgType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for MsgType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let v = u8::deserialize(deserializer)?;
        match v {
            1 => Ok(MsgType::Checkin),
            2 => Ok(MsgType::Beacon),
            3 => Ok(MsgType::Result),
            _ => Err(serde::de::Error::custom(format!("unknown msg type: {}", v))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "t")]
    pub msg_type: MsgType,

    #[serde(rename = "ts")]
    pub timestamp: i64,

    #[serde(rename = "n")]
    pub node_id: String,

    #[serde(
        rename = "p",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_payload",
        deserialize_with = "deserialize_payload",
        default
    )]
    pub payload: Option<Vec<u8>>,
}

fn serialize_payload<S: serde::Serializer>(
    data: &Option<Vec<u8>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match data {
        Some(bytes) => serializer.serialize_str(&BASE64.encode(bytes)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_payload<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Vec<u8>>, D::Error> {
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(encoded) => {
            let bytes = BASE64
                .decode(&encoded)
                .map_err(serde::de::Error::custom)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckinData {
    pub os: String,
    pub arch: String,
    pub host: String,
    pub pid: u32,

    #[serde(
        rename = "pk",
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub pub_key: Vec<u8>,
}

fn serialize_bytes<S: serde::Serializer>(
    data: &Vec<u8>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64.encode(data))
}

fn deserialize_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    BASE64.decode(&s).map_err(serde::de::Error::custom)
}

impl Envelope {
    pub fn new(msg_type: MsgType, node_id: &str, payload: Option<&[u8]>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Envelope {
            msg_type,
            timestamp,
            node_id: node_id.to_string(),
            payload: payload.map(|p| p.to_vec()),
        }
    }

    pub fn with_data<T: Serialize>(
        msg_type: MsgType,
        node_id: &str,
        data: &T,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let serialized = serde_json::to_vec(data)?;
        Ok(Self::new(msg_type, node_id, Some(&serialized)))
    }

    pub fn marshal(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let data = serde_json::to_vec(self)?;
        Ok(data)
    }
}

pub fn unmarshal(data: &[u8]) -> Result<Envelope, Box<dyn std::error::Error>> {
    let env: Envelope = serde_json::from_slice(data)?;
    Ok(env)
}