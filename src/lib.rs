#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate time;

use byteorder::LittleEndian;
use byteorder::{ReadBytesExt, WriteBytesExt};

use std::io::Cursor;
use std::io::Read;
use std::io::{Seek, SeekFrom};

bitflags! {
    pub flags Flags: u32 {
        const FLAG_UNICODE               = 0x00000001,
        const FLAG_OEM                   = 0x00000002,
        const FLAG_REQUEST_TARGET        = 0x00000004,
        const FLAG_SIGN                  = 0x00000010,
        const FLAG_SEAL                  = 0x00000020,
        const FLAG_DATAGRAM              = 0x00000040,
        const FLAG_LM_KEY                = 0x00000080,
        const FLAG_NTLM_KEY              = 0x00000200,
        const FLAG_ANONYMOUS             = 0x00000800,
        const FLAG_DOMAIN_SUPPLIED       = 0x00001000,
        const FLAG_WORKSTATION_SUPPLIFED = 0x00002000,
        const FLAG_ALWAYS_SIGN           = 0x00008000,
        const FLAG_TARGET_DOMAIN         = 0x00010000,
        const FLAG_TARGET_SERVER         = 0x00020000,
        const FLAG_EXTENDED_SECURITY     = 0x00080000,
        const FLAG_IDENTITY              = 0x00100000,
        const FLAG_NON_NT_SESSION        = 0x00400000,
        const FLAG_TARGET_INFO           = 0x00800000,
        const FLAG_VERSION               = 0x02000000,
        const FLAG_KEY_128               = 0x20000000,
        const FLAG_KEY_EXCHANGE          = 0x40000000,
        const FLAG_KEY_56                = 0x80000000,
    }
}

#[derive(Debug)]
pub enum Error {
    UnknownMessage,
}

#[derive(Debug, PartialEq)]
pub enum AvPair {
    Eol,
    NbComputerName(String),
    NbDomainName(String),
    DnsComputerName(String),
    DnsDomainName(String),
    DnsTreeName(String),
    Flags(u32),
    Timestamp(u32, u32),
    SingleHost(Vec<u8>),
    TargetName(String),
    ChannelBindings(Vec<u8>)
}

macro_rules! try_ntlm {
    ($e: expr) => {
        match $e {
            Ok(ok) => ok,
            Err(_err) => return Err(Error::UnknownMessage)
        }
    }
}

/// Negotiate Message
///
#[derive(Debug)]
pub struct Negotiate {
    pub flags: Flags,
    pub domain: String,
    pub workstation: String,
    pub version: Option<Version>,
}

impl<'a> Negotiate {
    pub fn from_bytes(buf: &'a [u8]) -> Result<Negotiate, Error> {
        let buf = &mut Cursor::new(buf);

        try_ntlm!(read_sig(buf));
        try_ntlm!(read_msg_ty(buf, NEG_MSG_TY));
        let flags = Flags::from_bits_truncate(try_ntlm!(read_u32(buf)));
        let domain = try_ntlm!(read_sec_buf(buf, read_utf16));
        let workstation = try_ntlm!(read_sec_buf(buf, read_utf16));
        let version = if flags.contains(FLAG_VERSION) {
            Some(try_ntlm!(read_version(buf)))
        } else {
            None
        };

        Ok(Negotiate {
            flags: flags,
            domain: domain,
            workstation: workstation,
            version: version,
        })
    }

    pub fn into_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl Default for Negotiate {
    fn default() -> Self {
        Negotiate {
            flags: FLAG_KEY_56            |
                   FLAG_KEY_EXCHANGE      |
                   FLAG_KEY_128           |
                   FLAG_EXTENDED_SECURITY |
                   FLAG_ALWAYS_SIGN       |
                   FLAG_NTLM_KEY          |
                   FLAG_SIGN              |
                   FLAG_REQUEST_TARGET    |
                   FLAG_UNICODE,
            domain: String::new(),
            workstation: String::new(),
            version: None,
        }
    }
}

/// Challenge Message
///
#[derive(Debug)]
pub struct Challenge {
    pub target_name: String,
    pub flags: Flags,
    pub challenge: u64,
    pub target_info: Vec<AvPair>,
    pub version: Option<Version>,
}

impl<'a> Challenge {
    pub fn from_bytes(buf: &'a [u8]) -> Result<Challenge, Error> {
        let buf = &mut Cursor::new(buf);

        try_ntlm!(read_sig(buf));
        try_ntlm!(read_msg_ty(buf, CHAL_MSG_TY));
        let target_name = try_ntlm!(read_sec_buf(buf, read_utf16));
        let flags = Flags::from_bits_truncate(try_ntlm!(read_u32(buf)));
        let challenge = try_ntlm!(read_u64(buf));
        let _reserved = try_ntlm!(read_u64(buf));
        let target_info = try_ntlm!(read_sec_buf(buf, read_av_pair_seq));
        let version = if flags.contains(FLAG_VERSION) {
            Some(try_ntlm!(read_version(buf)))
        } else {
            None
        };

        Ok(Challenge {
            target_name: target_name,
            flags: flags,
            challenge: challenge,
            target_info: target_info,
            version: version,
        })
    }

    pub fn into_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

/// Authenticate Message
///
#[derive(Debug)]
pub struct Authenticate {
    pub lm_resp: Vec<u8>,
    pub ntlm_resp: Vec<u8>,
    pub domain: String,
    pub user: String,
    pub workstation: String,
    pub session_key: Vec<u8>,
    pub flags: Flags,
    pub version: Option<Version>,
    pub mic: Vec<u8>,
}

impl<'a> Authenticate {
    pub fn from_bytes(buf: &'a [u8]) -> Result<Authenticate, Error> {
        let buf = &mut Cursor::new(buf);

        try_ntlm!(read_sig(buf));
        try_ntlm!(read_msg_ty(buf, AUTH_MSG_TY));
        let lm_resp = try_ntlm!(read_sec_buf(buf, read_u8v));
        let ntlm_resp = try_ntlm!(read_sec_buf(buf, read_u8v));
        let domain = try_ntlm!(read_sec_buf(buf, read_utf16));
        let user = try_ntlm!(read_sec_buf(buf, read_utf16));
        let workstation = try_ntlm!(read_sec_buf(buf, read_utf16));
        let session_key = try_ntlm!(read_sec_buf(buf, read_u8v));
        let flags = Flags::from_bits_truncate(try_ntlm!(read_u32(buf)));
        let version = if flags.contains(FLAG_VERSION) {
            Some(try_ntlm!(read_version(buf)))
        } else {
            None
        };
        let mic = try_ntlm!(read_u8v(buf, 16));

        Ok(Authenticate {
            lm_resp: lm_resp,
            ntlm_resp: ntlm_resp,
            domain: domain,
            user: user,
            workstation: workstation,
            session_key: session_key,
            flags: flags,
            version: version,
            mic: mic,
        })
    }

    pub fn into_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

/// Version
///
#[derive(Debug)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
    pub ntlm_rev: u8,
}

// helper functions
//
const NTLM_SIG: &'static [u8] = b"NTLMSSP\0";

const NEG_MSG_TY: u32  = 0x00000001;
const CHAL_MSG_TY: u32 = 0x00000002;
const AUTH_MSG_TY: u32 = 0x00000003;

const AV_EOL: u16               = 0x0000;
const AV_NB_COMPUTER_NAME: u16  = 0x0001;
const AV_NB_DOMAIN_NAME: u16    = 0x0002;
const AV_DNS_COMPUTER_NAME: u16 = 0x0003;
const AV_DNS_DOMAIN_NAME: u16   = 0x0004;
const AV_DNS_TREE_NAME: u16     = 0x0005;
const AV_FLAGS: u16             = 0x0006;
const AV_TIMESTAMP: u16         = 0x0007;
const AV_SINGLE_HOST: u16       = 0x0008;
const AV_TARGET_NAME: u16       = 0x0009;
const AV_CHANNEL_BINDINGS: u16  = 0x000A;

type CursorS<'a> = Cursor<&'a [u8]>;

fn read_sig(buf: &mut CursorS) -> Result<(), Error> {
    let mut sig = [0; 8];
    try_ntlm!(buf.read_exact(&mut sig));
    if sig == NTLM_SIG {
        Ok(())
    } else {
        Err(Error::UnknownMessage)
    }
}

fn read_msg_ty(buf: &mut CursorS, ty: u32) -> Result<(), Error> {
    let t = try_ntlm!(read_u32(buf));
    if t == ty {
        Ok(())
    } else {
        Err(Error::UnknownMessage)
    }
}

fn read_sec_buf<T>(buf: &mut CursorS, f: fn(&mut CursorS, u16) -> Result<T, Error>) -> Result<T, Error> {
    let len = try_ntlm!(read_u16(buf));
    let _maxlen = try_ntlm!(read_u16(buf));
    let off = try_ntlm!(read_u32(buf));

    let old_pos = buf.position();
    let _new_pos = try_ntlm!(buf.seek(SeekFrom::Start(off as u64)));
    let ret = try_ntlm!(f(buf, len));
    let _new_pos = try_ntlm!(buf.seek(SeekFrom::Start(old_pos)));
    Ok(ret)
}

fn read_av_pair_seq(buf: &mut CursorS, _len: u16) -> Result<Vec<AvPair>, Error> {
    let mut ret = vec![];
    loop {
        let av = try_ntlm!(read_av_pair(buf));
        if av == AvPair::Eol {
            break;
        }
        ret.push(av);
    }
    Ok(ret)
}

fn read_av_pair(buf: &mut CursorS) -> Result<AvPair, Error> {
    let id = try_ntlm!(read_u16(buf));
    let len = try_ntlm!(read_u16(buf));

    use AvPair::*;
    match id {
        AV_EOL               => Ok(Eol),
        AV_NB_COMPUTER_NAME  => Ok(NbComputerName(try_ntlm!(read_utf16(buf, len)))),
        AV_NB_DOMAIN_NAME    => Ok(NbDomainName(try_ntlm!(read_utf16(buf, len)))),
        AV_DNS_COMPUTER_NAME => Ok(DnsComputerName(try_ntlm!(read_utf16(buf, len)))),
        AV_DNS_DOMAIN_NAME   => Ok(DnsDomainName(try_ntlm!(read_utf16(buf, len)))),
        AV_DNS_TREE_NAME     => Ok(DnsTreeName(try_ntlm!(read_utf16(buf, len)))),
        AV_FLAGS             => Ok(Flags(try_ntlm!(read_u32(buf)))),
        AV_TIMESTAMP         => Ok(Timestamp(try_ntlm!(read_u32(buf)), try_ntlm!(read_u32(buf)))),
        AV_SINGLE_HOST       => Ok(SingleHost(try_ntlm!(read_u8v(buf, len)))),
        AV_TARGET_NAME       => Ok(TargetName(try_ntlm!(read_utf16(buf, len)))),
        AV_CHANNEL_BINDINGS  => Ok(ChannelBindings(try_ntlm!(read_u8v(buf, len)))),
        _                    => Err(Error::UnknownMessage)
    }
}

fn read_utf16(buf: &mut CursorS, len: u16) -> Result<String, Error> {
    if len == 0 {
        return Ok(String::new());
    }
    let u16v = try_ntlm!(read_u16v(buf, len));
    Ok(try_ntlm!(String::from_utf16(&u16v)))
}

fn read_version(buf: &mut CursorS) -> Result<Version, Error> {
    let major = try_ntlm!(read_u8(buf));
    let minor = try_ntlm!(read_u8(buf));
    let build = try_ntlm!(read_u16(buf));
    let _reserved = try_ntlm!(read_u16(buf));
    let _reserved = try_ntlm!(read_u8(buf));
    let rev = try_ntlm!(read_u8(buf));
    Ok(Version {
        major: major,
        minor: minor,
        build: build,
        ntlm_rev: rev,
    })
}

fn read_u16v(buf: &mut CursorS, len: u16) -> Result<Vec<u16>, Error> {
    assert_eq!(len % 2, 0);

    let mut v = vec![];
    let mut n = 0;
    while n < len {
        v.push(try_ntlm!(read_u16(buf)));
        n += 2;
    }
    Ok(v)
}

fn read_u8v(buf: &mut CursorS, len: u16) -> Result<Vec<u8>, Error> {
    let mut v = vec![0; len as usize];
    try_ntlm!(buf.read_exact(&mut v));
    Ok(v)
}

fn read_u64(buf: &mut CursorS) -> Result<u64, Error> {
    Ok(try_ntlm!(buf.read_u64::<LittleEndian>()))
}

fn read_u32(buf: &mut CursorS) -> Result<u32, Error> {
    Ok(try_ntlm!(buf.read_u32::<LittleEndian>()))
}

fn read_u16(buf: &mut CursorS) -> Result<u16, Error> {
    Ok(try_ntlm!(buf.read_u16::<LittleEndian>()))
}

fn read_u8(buf: &mut CursorS) -> Result<u8, Error> {
    Ok(try_ntlm!(buf.read_u8()))
}
