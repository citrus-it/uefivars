use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use serde::Serialize;
use serde::Serializer;

use binrw::helpers::{until, until_eof, until_exclusive};
use binrw::io::{Cursor, SeekFrom};
use binrw::{binread, binrw, BinReaderExt};

// The uefi-edk2 nvram firmware volume is divided into sections as follows:
//
//  0x00000 - 0x0dfff     NV_VARIABLE_STORE (Firmware volume)
//  0x0e000 - 0x0efff     NV_EVENT_LOG
//  0x0f000 - 0x0ffff     NV_FTW_WORKING (Fault-tolerant-write)
//  0x10000 - 0x1ffff     NV_FTW_SPARE
//
// This is valid for firmware generated with an FD_SIZE of 1024 or 2048
// I have yet to see anything in the event log area, but it is preserved
// when rewriting.

const NV_EVENT_LOG: u64     = 0xe000;
const NV_EVENT_LOG_LEN: u64 = 0x1000;
const NV_FTW_WORKING: u64   = 0xf000;
//const NV_FTW_SPARE: u64     = 0x10000;

const EFI_SYSTEM_NV_DATA_FV_GUID: EfiGuid = EfiGuid {
    data1: 0xfff1_2b8d,
    data2: 0x7696,
    data3: 0x4c8b,
    data4: [0xa9, 0x85, 0x27, 0x47, 0x7, 0x5b, 0x4f, 0x50],
};

const EFI_AUTHENTICATED_VARIABLE_GUID: EfiGuid = EfiGuid {
    data1: 0xaaf3_2c78,
    data2: 0x947b,
    data3: 0x439a,
    data4: [0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92],
};

const EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER: EfiGuid = EfiGuid {
    data1: 0x9e58292b,
    data2: 0x7c68,
    data3: 0x497d,
    data4: [0xa0, 0xce, 0x65, 0x0, 0xfd, 0x9f, 0x1b, 0x95],
};

pub const EFI_GLOBAL_VARIABLE_GUID: EfiGuid = EfiGuid {
    data1: 0x8be4_df61,
    data2: 0x93ca,
    data3: 0x11d2,
    data4: [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
};

const VARIABLE_DATA: u16        = 0x55aa;

const VAR_STORE_FORMATTED: u8   = 0x5a;
const VAR_STORE_HEALTHY: u8     = 0xfe;

pub const VAR_ADDED: u8             = 0x3f;
const VAR_DELETED: u8               = 0xfd;
const VAR_IN_DELETED_TRANSITION: u8 = 0xfe;
const VAR_HEADER_VALID_ONLY: u8     = 0x7f;
const VAR_ADDED_TRANSITION: u8      = VAR_ADDED & VAR_IN_DELETED_TRANSITION;
const VAR_DELETED_TRANSITION: u8    =
    VAR_ADDED & VAR_DELETED & VAR_IN_DELETED_TRANSITION;

#[binrw]
#[allow(dead_code)]
#[derive(Debug)]
pub struct Volume {
    #[br(assert(zero_vector == 0))]
    zero_vector:        u128,
    #[br(assert(guid == EFI_SYSTEM_NV_DATA_FV_GUID,
        "Unexpected GUID in file, got {:#x?}", guid))]
    guid:               EfiGuid,
    pub volsize:        u64,
    #[br(assert(signature == 0x4856465f))] // "_FVH"
    signature:          u32,
    attributes:         u32,
    headerlen:          u16,
    checksum:           u16,
    #[br(assert(ext_hdr_offset == 0))]  // Cannot handle extended headers
    ext_hdr_offset:     u16,
    #[br(assert(_rsvd1 == 0))]
    _rsvd1:             u8,
    #[br(assert(revision == 2))]
    revision:           u8,
    #[br(parse_with = until(|&b: &BlockMapEntry|
        b.num == 0 && b.len == 0))]
    maps:               Vec<BlockMapEntry>,
    // Is this a bug in binrw? When using 'until', the cursor ends up one block
    // too far on so it needs to be rewinded by sizeof (BlockMapEntry).
    #[br(seek_before(SeekFrom::Current(-8)))]
    header:             VariableStoreHeader,
    #[br(parse_with = until_exclusive(|v: &AuthVariable|
        v.startid != VARIABLE_DATA
    ))]
    pub vars:           Vec<AuthVariable>,

    // There is a gap here, which is filled with 0xff in the original
    // (possibly emulating erased flash).
    // When it's written back, it ends up being zeroed.

    #[brw(seek_before(SeekFrom::Start(NV_EVENT_LOG)))]
    #[br(count = NV_EVENT_LOG_LEN)]
    eventlog:           Vec<u8>,

    // TBD: Always replace this with a clean block, or preserve?
    #[brw(seek_before(SeekFrom::Start(NV_FTW_WORKING)))]
    ftw:                FTWBlockHeader,
    #[br(parse_with = until_eof)]
    ftwdata:            Vec<u8>,
}

#[binrw]
#[allow(dead_code)]
#[derive(Debug)]
pub struct VariableStoreHeader {
    // uefi-edk2 ships an authenticated variable store
    #[br(assert(guid == EFI_AUTHENTICATED_VARIABLE_GUID,
        "Unexpected store header GUID, got {:#x?}", guid))]
    guid:               EfiGuid,
    size:               u32,
    #[br(assert(format == VAR_STORE_FORMATTED))]
    format:             u8,
    #[br(assert(state == VAR_STORE_HEALTHY))]
    state:              u8,
    _rsvd1:             u16,
    _rsvd2:             u32,
}

#[binrw]
#[allow(dead_code)]
#[derive(Debug)]
pub struct FTWBlockHeader {
    #[br(assert(guid == EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER,
        "Unexpected FTW header GUID, got {:#x?}", guid))]
    guid:               EfiGuid,
    crc32:              u32,
    flags:              u32,
    queuesize:          u64,
}

#[binrw]
#[allow(dead_code)]
#[derive(Serialize, Debug)]
pub struct AuthVariable {
    pub startid:        u16,
    pub state:          u8,
    #[serde(skip)]
    pub _rsvd1:         u8,
    pub attributes:     u32,
    #[serde(skip)]
    pub count:          u64,
    #[serde(skip)]
    pub timestamp:      EfiTime,
    #[serde(skip)]
    pub pubkeyindex:    u32,
    pub namelen:        u32,
    pub datalen:        u32,
    pub guid:           EfiGuid,
    #[br(if(startid == VARIABLE_DATA))]
    #[br(parse_with = utf16::read, args((namelen)))]
    #[bw(write_with = utf16::write)]
    pub name:           String,
    #[br(if(startid == VARIABLE_DATA))]
    #[br(count = datalen)]
    #[brw(align_after = 4)]
    pub data:           Vec<u8>,
}

const EFI_VARIABLE_NON_VOLATILE: u32                           = 0x00000001;
const EFI_VARIABLE_BOOTSERVICE_ACCESS: u32                     = 0x00000002;
const EFI_VARIABLE_RUNTIME_ACCESS: u32                         = 0x00000004;
const EFI_VARIABLE_HARDWARE_ERROR_RECORD: u32                  = 0x00000008;
const EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32  = 0x00000020;
const EFI_VARIABLE_APPEND_WRITE: u32                           = 0x00000040;

impl fmt::Display for AuthVariable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let m = min(self.data.len(), 7);
        let guid = match resolve_guid(&self.guid) {
            Some(s) => s.to_string(),
            None    => self.guid.to_string(),
        };
        let mut attrlist = Vec::new();

        if self.attributes & EFI_VARIABLE_NON_VOLATILE != 0 {
            attrlist.push("NV");
        }

        if self.attributes & EFI_VARIABLE_RUNTIME_ACCESS != 0 {
            attrlist.push("RT");
            attrlist.push("BS");
        } else if self.attributes & EFI_VARIABLE_BOOTSERVICE_ACCESS != 0 {
            attrlist.push("BS");
        }

        if self.attributes & EFI_VARIABLE_HARDWARE_ERROR_RECORD != 0 {
            attrlist.push("HR");
        }

        if self.attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
            != 0
        {
            attrlist.push("AT");
        }

        if self.attributes & EFI_VARIABLE_APPEND_WRITE != 0 {
            attrlist.push("AW");
        }

        let statestr = format!("{:02x}?", self.state);

        let state = match self.state {
            VAR_ADDED                       => "   ",
            VAR_ADDED_TRANSITION            => "ADT",
            VAR_DELETED                     => "DEL",
            VAR_DELETED_TRANSITION          => "DEL",
            VAR_HEADER_VALID_ONLY           => "HVO",
            _                               => &statestr,
        };

        write!(f, "{:^40} {} {:^10} {} {:?}{}",
            guid, state, attrlist.join("+"), self.name,
            &self.data[..m],
            if self.data.len() > m {
                format!("..{}", self.data.len() - 1)
            } else {
                "".to_string()
            }
        )
    }
}

impl Default for AuthVariable {
    fn default() -> Self {
        Self {
            startid:        VARIABLE_DATA,
            state:          VAR_ADDED,
            _rsvd1:         0,
            attributes:     EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_RUNTIME_ACCESS,
            count:          0,
            timestamp:      EfiTime::default(),
            pubkeyindex:    0,
            namelen:        0,
            datalen:        0,
            guid:           EFI_GLOBAL_VARIABLE_GUID.clone(),
            name:           "".to_string(),
            data:           Vec::new(),
        }
    }
}

impl Volume {

    pub fn boot_entries(&self) -> BootEntryIter {
        // XXX - just store the iterator in the struct?
        let mut vars: Vec<&AuthVariable> = self.vars.iter().filter(|&v|
                v.name.starts_with("Boot0") &&
                v.state == VAR_ADDED &&
                v.guid.to_string() == EFI_GLOBAL_VARIABLE_GUID.to_string())
                .collect();
        vars.reverse();
        BootEntryIter { vars }
    }

    pub fn defrag(&mut self) {
        // To de-fragment a variables file, one needs to:
        // - preserve all VAR_ADDED variables
        // - promote VAR_IN_DELETED_TRANSITION variables to VAR_ADDED providing
        //   there is not already a VAR_ADDED variable with the same GUID and
        //   name.
        // - remove anything remaining that is not VAR_ADDED.

        // Build a list of VAR_ADDED
        let mut known: HashSet<String> = HashSet::new();
        for v in &self.vars {
            if v.state == VAR_ADDED {
                known.insert(format!("{}/{}", v.guid, v.name).to_string());
            }
        }

        self.vars.retain(|v| {
            v.state == VAR_ADDED
                || (v.state == (VAR_ADDED & VAR_IN_DELETED_TRANSITION)
                    && !known.contains(
                        &format!("{}/{}", v.guid, v.name),
                    ))
        });

        // Now promote any remaining ADDED/IN_DELETED_TRANSITION entries
        for v in &mut self.vars {
            v.state = VAR_ADDED;
        }
    }

    pub fn remove_var(&mut self, name: &str, guid: &str) {
        self.vars.retain(|v| v.name != name || v.guid.to_string() != guid);
    }

    pub fn find_var(&self, name: &str, guid: &str) -> Option<&AuthVariable> {
        for v in &self.vars {
            if v.state == VAR_ADDED
                && v.name == name
                && v.guid.to_string() == guid
            {
                return Some(v);
            }
        }
        None
    }

    pub fn set_u16_var(&mut self, name: &str, data: &[u16]) {
        self.remove_var(name, &EFI_GLOBAL_VARIABLE_GUID.to_string());

        let ndata = data
            .iter()
            .map(|&x| x.to_le_bytes())
            .collect::<Vec<[u8; 2]>>()
            .concat();

        let var = AuthVariable {
            name: name.to_string(),
            namelen: (name.len() as u32 + 1) * 2,
            datalen: ndata.len() as u32,
            data: ndata,
            ..Default::default()
        };
        self.vars.push(var);
    }

    pub fn boot_order(&self) -> Option<BootOrder> {
        if let Some(cv) =
            self.find_var("BootOrder", &EFI_GLOBAL_VARIABLE_GUID.to_string())
        {
            if cv.datalen > 1 {
                let mut c = Cursor::new(&cv.data);
                let bo: BootOrder = c.read_le().unwrap();
                return Some(bo);
            }
        }
        None
    }

    pub fn boot_next(&self) -> Option<u16> {
        if let Some(nv) =
            self.find_var("BootNext", &EFI_GLOBAL_VARIABLE_GUID.to_string())
        {
            if nv.datalen > 1 {
                return Some((nv.data[0] as u16) | ((nv.data[1] as u16) << 8));
            }
        }
        None
    }
}

#[binrw]
#[derive(PartialEq, Debug, Clone, Default)]
pub struct EfiGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl fmt::Display for EfiGuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-\
            {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3, self.data4[0], self.data4[1],
            self.data4[2], self.data4[3], self.data4[4], self.data4[5],
            self.data4[6], self.data4[7])
    }
}

impl FromStr for EfiGuid {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            panic!("Invalid number of parts in guid");
        }
        let mut guid = EfiGuid::default();
        guid.data1 = u32::from_str_radix(parts[0], 16)?;
        guid.data2 = u16::from_str_radix(parts[1], 16)?;
        guid.data3 = u16::from_str_radix(parts[2], 16)?;
        guid.data4[0] = u8::from_str_radix(&parts[3][..2], 16)?;
        guid.data4[1] = u8::from_str_radix(&parts[3][2..], 16)?;
        let mut i = 2;
        for b in parts[4].as_bytes().chunks(2) {
            let s = std::str::from_utf8(b).unwrap();
            guid.data4[i] = u8::from_str_radix(s, 16)?;
            i += 1
        }
        Ok(guid)
    }
}

impl Serialize for EfiGuid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::IntErrorKind;

    #[test]
    fn guid_to_str() {
        assert_eq!(
            EFI_GLOBAL_VARIABLE_GUID.to_string(),
            "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        );
    }

    #[test]
    fn guid_from_str() {
        assert_eq!(
            EfiGuid::from_str("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            Ok(EFI_GLOBAL_VARIABLE_GUID)
        );
    }

    #[test]
    fn guid_from_str_err() {
        let err = EfiGuid::from_str("xbe4df61-93ca-11d2-aa0d-00e098032b8c")
            .unwrap_err();
        let kind = err.kind();
        assert_eq!(kind, &IntErrorKind::InvalidDigit);
        let err = EfiGuid::from_str("018be4df61-93ca-11d2-aa0d-00e098032b8c")
            .unwrap_err();
        let kind = err.kind();
        assert_eq!(kind, &IntErrorKind::PosOverflow);
    }
}

#[binrw]
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct EfiTime {
    year:       u16,
    month:      u8,
    day:        u8,
    hour:       u8,
    min:        u8,
    sec:        u8,
    _pad1:      u8,
    nanosec:    u32,
    tz:         u16,
    daylight:   u8,
    _pad2:      u8,
}

impl fmt::Display for EfiTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{}",
            self.year, self.month, self.day,
            self.hour, self.min, self.sec,
            self.nanosec)
    }
}

impl Serialize for EfiTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[binrw]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub struct BlockMapEntry {
    num: u32,
    len: u32,
}

#[binread]
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct BootOrder {
    #[br(restore_position)]
    pub first: u16,
    #[br(parse_with = until_eof)]
    pub order: Vec<u16>,
}

// See section 3.1.3 of the UEFI specification, version 2.9, for the
// EFI_LOAD_OPTION structure.
#[binread]
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct BootEntry {
    #[br(ignore)]
    pub slot:           u16,
    #[br(ignore)]
    pub name:           String,
    #[br(ignore)]
    pub title:          String,

    pub attributes:     u32,
    #[serde(skip)]
    fplength:           u16,
    #[serde(skip)]
    #[br(parse_with = until_exclusive(|v| *v == 0))]
    pub rawtitle:       Vec<u16>,

    #[br(parse_with =
        until_exclusive(|v: &DevicePath|
        v.device_type == 0x7f && v.sub_type == 0xff))]
    pub pathlist:       Vec<DevicePath>,
    #[br(parse_with = until_eof)]
    pub optionaldata:   Vec<u8>,

    #[br(ignore)]
    pub btype:          BootEntryType,

    #[br(ignore)]
    pub uri:            bool
}

#[derive(Serialize)]
pub enum BootEntryType {
    Unknown,
    PCI(u8, u8),
    App(EfiGuid),
    Path(String),
}

impl Default for BootEntryType {
    fn default() -> Self {
        BootEntryType::Unknown
    }
}

impl fmt::Debug for BootEntryType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}",
            match self {
                BootEntryType::PCI(f, d) =>
                    format!("PCI {}.{}", d, f),
                BootEntryType::App(ref guid) =>
                    format!("App {}", guid),
                BootEntryType::Path(ref path) =>
                    format!("Path {}", path),
                BootEntryType::Unknown => "unknown".to_string(),
            }
        )
    }
}

// Section 10.3.1 - Generic Device Path Structures
#[binread]
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct DevicePath {
    // header
    pub device_type:    u8,
    pub sub_type:       u8,
    pub length:         u16,
    #[br(count = length - 4)]
    pub data:           Vec<u8>,
}

#[binread]
pub struct RawUTF16 {
    #[br(parse_with = until_exclusive(|v| *v == 0))]
    pub raw:        Vec<u16>,
}

#[allow(dead_code)]
pub enum DeviceType {
    HardwareDevicePath = 1,
    ACPIDevicePath = 2,
    MessagingDevicePath = 3,
    MediaDevicePath = 4,
    BIOSDevicePath = 5,
    EOD = 0x7f,
}

pub const LOAD_OPTION_HIDDEN: u32 = 0x8;

pub struct BootEntryIter<'v> {
    vars: Vec<&'v AuthVariable>,
}

impl Iterator for BootEntryIter<'_> {
    type Item = BootEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(entry) = self.vars.pop() {
            let mut c = Cursor::new(&entry.data);
            let mut elo: Self::Item = c.read_le().unwrap();

            elo.name = entry.name.clone();
            elo.slot = u16::from_str_radix(&elo.name[5..], 16).unwrap_or(0);
            elo.title = String::from_utf16_lossy(elo.rawtitle.as_slice());

            for p in &elo.pathlist {
                // 10.3.2.1 PCI Device Path
                if p.device_type == 1 && p.sub_type == 1 && p.data.len() == 2 {
                    elo.btype = BootEntryType::PCI(p.data[0], p.data[1]);
                }
                // 10.3.5.6 PIWG Firmware File
                if p.device_type == 4 && p.sub_type == 6 &&
                    p.data.len() == 16 {

                    let mut pc = Cursor::new(&p.data);
                    let guid: EfiGuid = pc.read_le().unwrap();
                    elo.btype = BootEntryType::App(guid);
                }
                // 10.3.4.23 Uniform Resource Identifiers (URI) Device Path
                if p.device_type == 3 && p.sub_type == 24 {
                    elo.uri = true;
                }
                // 10.3.5.4 File Path Media Device Path
                if p.device_type == 4 && p.sub_type == 4 {
                    let mut pc = Cursor::new(&p.data);
                    let rawpath: RawUTF16 = pc.read_le().unwrap();
                    let path = String::from_utf16_lossy(rawpath.raw.as_slice());
                    elo.btype = BootEntryType::Path(path);
                }
            }

            Some(elo)
        } else {
            None
        }
    }
}

mod utf16 {
    use binrw::io::prelude::*;
    use binrw::prelude::*;
    use binrw::ReadOptions;
    use binrw::WriteOptions;
    use std::char::{decode_utf16, REPLACEMENT_CHARACTER};

    pub fn read<R>(
        reader: &mut R, _ro: &ReadOptions, args: (u32,),
    ) -> BinResult<String>
    where
        R: Read + Seek,
    {
        let mut i = args.0 as usize;
        let mut v: Vec<u16> = Vec::with_capacity(i / 2);

        while i > 0 {
            let ch: u16 = reader.read_le().unwrap();
            if ch != 0 {
                v.push(ch);
            }
            i -= 2
        }
        let s = decode_utf16(v.iter().cloned())
            .map(|r| r.unwrap_or(REPLACEMENT_CHARACTER))
            .collect::<String>();

        Ok(s)
    }

    pub fn write<W>(
        data: &String, writer: &mut W, wo: &WriteOptions, _: (),
    ) -> binrw::BinResult<()>
    where
        W: binrw::io::Write + binrw::io::Seek,
    {
        let mut v: Vec<u16> = data.encode_utf16().collect();
        v.push(0);

        v.write_options(writer, wo, ())?;
        Ok(())
    }
}

pub fn resolve_guid(guid: &EfiGuid) -> Option<&str> {
    KNOWN_GUIDS.get(guid.to_string().as_str()).cloned()
}

lazy_static! {
    static ref KNOWN_GUIDS: HashMap<&'static str, &'static str> = {
        // Ones seen in use with bhyve guests
        [
            ("8be4df61-93ca-11d2-aa0d-00e098032b8c",
                "GLOBAL_VARIABLE"),
            ("04b37fe8-f6ae-480b-bdd5-37d98c5e89aa",
                "EDKII_VAR_ERROR_FLAG"),
            ("59324945-ec44-4c0d-b1cd-9db139df070c",
                "EFI_ISCSI_INITIATOR_NAME_PROTOCOL_GUID"),
            ("5b446ed1-e30b-4faa-871a-3654eca36080",
                "EFI_IP4_CONFIG2_PROTOCOL_GUID"),
            ("4c19049f-4137-4dd3-9c10-8b97a83ffdfa",
                "EFI_MEMORY_TYPE_INFORMATION_GUID"),
            ("fab7e9e1-39dd-4f2b-8408-e20e906cb6de",
                "HD_BOOT_DEVICE_PATH_VARIABLE"),
            ("eb704011-1402-11d3-8e77-00a0c969723b",
                "MTC_VENDOR"),
            ("4b47d616-a8d6-4552-9d44-ccad2e0f4cf9",
                "ISCSI_CONFIG"),
            ("77fa9abd-0359-4d32-bd60-28f4e78f784b",
                "SecureBootPlatformID"),
            ("eaec226f-c9a3-477a-a826-ddc716cdc0e3",
                "WindowsID"),

            // Others
            ("00720665-67eb-4a99-baf7-d3c33a1c7cc9",
                "EFI_TCP4_SERVICE_BINDING_PROTOCOL_GUID"),
            ("02e800be-8f01-4aa6-946b-d71388e1833f",
                "EFI_MTFTP4_SERVICE_BINDING_PROTOCOL_GUID"),
            ("0379be4e-d706-437d-b037-edb82fb772a4",
                "EFI_DEVICE_PATH_UTILITIES_PROTOCOL_GUID"),
            ("03c4e603-ac28-11d3-9a2d-0090273fc14d",
                "EFI_PXE_BASE_CODE_PROTOCOL_GUID"),
            ("05ad34ba-6f02-4214-952e-4da0398e2bb9",
                "EFI_DXE_SERVICES_TABLE_GUID"),
            ("09576e91-6d3f-11d2-8e39-00a0c969723b",
                "EFI_DEVICE_PATH_PROTOCOL_GUID"),
            ("09576e92-6d3f-11d2-8e39-00a0c969723b",
                "EFI_FILE_INFO_ID"),
            ("09576e93-6d3f-11d2-8e39-00a0c969723b",
                "EFI_FILE_SYSTEM_INFO_ID"),
            ("0db48a36-4e54-ea9c-9b09-1ea5be3a660b",
                "EFI_REST_PROTOCOL_GUID"),
            ("0faaecb1-226e-4782-aace-7db9bcbf4daf",
                "EFI_FTP4_SERVICE_BINDING_PROTOCOL_GUID"),
            ("107a772c-d5e1-11d4-9a46-0090273fc14d",
                "EFI_COMPONENT_NAME_PROTOCOL_GUID"),
            ("11b34006-d85b-4d0a-a290-d5a571310ef7",
                "PCD_PROTOCOL_GUID"),
            ("13a3f0f6-264a-3ef0-f2e0-dec512342f34",
                "EFI_PCD_PROTOCOL_GUID"),
            ("13ac6dd1-73d0-11d4-b06b-00aa00bd6de7",
                "EFI_EBC_INTERPRETER_PROTOCOL_GUID"),
            ("143b7632-b81b-4cb7-abd3-b625a5b9bffe",
                "EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID"),
            ("151c8eae-7f2c-472c-9e54-9828194f6a88",
                "EFI_DISK_IO2_PROTOCOL_GUID"),
            ("1682fe44-bd7a-4407-b7c7-dca37ca3922d",
                "EFI_TLS_CONFIGURATION_PROTOCOL_GUID"),
            ("18a031ab-b443-4d1a-a5c0-0c09261e9f71",
                "EFI_DRIVER_BINDING_PROTOCOL_GUID"),
            ("1c0c34f6-d380-41fa-a049-8ad06c1a66aa",
                "EFI_EDID_DISCOVERED_PROTOCOL_GUID"),
            ("1d3de7f0-0807-424f-aa69-11a54e19a46f",
                "EFI_ATA_PASS_THRU_PROTOCOL_GUID"),
            ("2755590c-6f3c-42fa-9ea4-a3ba543cda25",
                "EFI_DEBUG_SUPPORT_PROTOCOL_GUID"),
            ("2a534210-9280-41d8-ae79-cada01a2b127",
                "EFI_DRIVER_HEALTH_PROTOCOL_GUID"),
            ("2c8759d5-5c2d-66ef-925f-b66c101957e2",
                "EFI_IP6_PROTOCOL_GUID"),
            ("2f707ebb-4a1a-11d4-9a38-0090273fc14d",
                "EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_GUID"),
            ("31878c87-0b75-11d5-9a4f-0090273fc14d",
                "EFI_SIMPLE_POINTER_PROTOCOL_GUID"),
            ("31a6406a-6bdf-4e46-b2a2-ebaa89c40920",
                "EFI_HII_IMAGE_PROTOCOL_GUID"),
            ("330d4706-f2a0-4e4f-a369-b66fa8d54385",
                "EFI_HII_CONFIG_ACCESS_PROTOCOL_GUID"),
            ("387477c1-69c7-11d2-8e39-00a0c969723b",
                "EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID"),
            ("387477c2-69c7-11d2-8e39-00a0c969723b",
                "EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID"),
            ("39b68c46-f7fb-441b-b6ec-16b0f69821f3",
                "EFI_CAPSULE_REPORT_GUID"),
            ("3ad9df29-4501-478d-b1f8-7f7fe70e50f3",
                "EFI_UDP4_PROTOCOL_GUID"),
            ("3b95aa31-3793-434b-8667-c8070892e05e",
                "EFI_IP4_CONFIG_PROTOCOL_GUID"),
            ("3e35c163-4074-45dd-431e-23989dd86b32",
                "EFI_HTTP_UTILITIES_PROTOCOL_GUID"),
            ("3e745226-9818-45b6-a2ac-d7cd0e8ba2bc",
                "EFI_USB2_HC_PROTOCOL_GUID"),
            ("41d94cd2-35b6-455a-8258-d4e51334aadd",
                "EFI_IP4_PROTOCOL_GUID"),
            ("49152e77-1ada-4764-b7a2-7afefed95e8b",
                "EFI_DEBUG_IMAGE_INFO_TABLE_GUID"),
            ("4cf5b200-68b8-4ca5-9eec-b23e3f50029a",
                "EFI_PCI_IO_PROTOCOL_GUID"),
            ("4d330321-025f-4aac-90d8-5ed900173b63",
                "EFI_DRIVER_DIAGNOSTICS_PROTOCOL_GUID"),
            ("4f948815-b4b9-43cb-8a33-90e060b34955",
                "EFI_UDP6_PROTOCOL_GUID"),
            ("587e72d7-cc50-4f79-8209-ca291fc1a10f",
                "EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID"),
            ("5b1b31a1-9562-11d2-8e3f-00a0c969723b",
                "EFI_LOADED_IMAGE_PROTOCOL_GUID"),
            ("5c198761-16a8-4e69-972c-89d67954f81d",
                "EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL_GUID"),
            ("65530bc7-a359-410f-b010-5aadc7ec2b62",
                "EFI_TCP4_PROTOCOL_GUID"),
            ("66ed4721-3c98-4d3e-81e3-d03dd39a7254",
                "EFI_UDP6_SERVICE_BINDING_PROTOCOL_GUID"),
            ("6a1ee763-d47a-43b4-aabe-ef1de2ab56fc",
                "EFI_HII_PACKAGE_LIST_PROTOCOL_GUID"),
            ("6a7a5cff-e8d9-4f70-bada-75ab3025ce14",
                "EFI_COMPONENT_NAME2_PROTOCOL_GUID"),
            ("6b30c738-a391-11d4-9a3b-0090273fc14d",
                "EFI_PLATFORM_DRIVER_OVERRIDE_PROTOCOL_GUID"),
            ("7739f24c-93d7-11d4-9a3a-0090273fc14d",
                "EFI_HOB_LIST_GUID"),
            ("78247c57-63db-4708-99c2-a8b4a9a61f6b",
                "EFI_MTFTP4_PROTOCOL_GUID"),
            ("783658a3-4172-4421-a299-e009079c0cb4",
                "EFI_LEGACY_BIOS_PLATFORM_PROTOCOL_GUID"),
            ("7a59b29b-910b-4171-8242-a85a0df25b5b",
                "EFI_HTTP_PROTOCOL_GUID"),
            ("7ab33a91-ace5-4326-b572-e7ee33d39f16",
                "EFI_MANAGED_NETWORK_PROTOCOL_GUID"),
            ("7f1647c8-b76e-44b2-a565-f70ff19cd19e",
                "EFI_DNS6_SERVICE_BINDING_PROTOCOL_GUID"),
            ("83f01464-99bd-45e5-b383-af6305d8e9e6",
                "EFI_UDP4_SERVICE_BINDING_PROTOCOL_GUID"),
            ("87c8bad7-0595-4053-8297-dede395f5d5b",
                "EFI_DHCP6_PROTOCOL_GUID"),
            ("8868e871-e4f1-11d3-bc22-0080c73c8881",
                "EFI_ACPI_TABLE_GUID"),
            ("8a219718-4ef5-4761-91c8-c0f04bda9e56",
                "EFI_DHCP4_PROTOCOL_GUID"),
            ("8b843e20-8132-4852-90cc-551a4e4a7f1c",
                "EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID"),
            ("8d59d32b-c655-4ae9-9b15-f25904992a43",
                "EFI_ABSOLUTE_POINTER_PROTOCOL_GUID"),
            ("9042a9de-23dc-4a38-96fb-7aded080516a",
                "EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID"),
            ("937fe521-95ae-4d1a-8929-48bcd90ad31a",
                "EFI_IP6_CONFIG_PROTOCOL_GUID"),
            ("952cb795-ff36-48cf-a249-4df486d6ab8d",
                "EFI_TLS_SERVICE_BINDING_PROTOCOL_GUID"),
            ("964e5b21-6459-11d2-8e39-00a0c969723b",
                "EFI_BLOCK_IO_PROTOCOL_GUID"),
            ("964e5b22-6459-11d2-8e39-00a0c969723b",
                "EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID"),
            ("9d9a39d8-bd42-4a73-a4d5-8ee94be11380",
                "EFI_DHCP4_SERVICE_BINDING_PROTOCOL_GUID"),
            ("9e23d768-d2f3-4366-9fc3-3a7aba864374",
                "EFI_VLAN_CONFIG_PROTOCOL_GUID"),
            ("9fb9a8a1-2f4a-43a6-889c-d0f7b6c47ad5",
                "EFI_DHCP6_SERVICE_BINDING_PROTOCOL_GUID"),
            ("a3979e64-ace8-4ddc-bc07-4d66b8fd0977",
                "EFI_IPSEC2_PROTOCOL_GUID"),
            ("a4c751fc-23ae-4c3e-92e9-4964cf63f349",
                "EFI_UNICODE_COLLATION_PROTOCOL2_GUID"),
            ("a77b2472-e282-4e9f-a245-c2c0e27bbcc1",
                "EFI_BLOCK_IO2_PROTOCOL_GUID"),
            ("ae3d28cc-e05b-4fa1-a011-7eb55a3f1401",
                "EFI_DNS4_PROTOCOL_GUID"),
            ("b625b186-e063-44f7-8905-6a74dc6f52b4",
                "EFI_DNS4_SERVICE_BINDING_PROTOCOL_GUID"),
            ("b9d4c360-bcfb-4f9b-9298-53c136982258",
                "EFI_FORM_BROWSER2_PROTOCOL_GUID"),
            ("bb25cf6f-f1d4-11d2-9a0c-0090273fc1fd",
                "EFI_SERIAL_IO_PROTOCOL_GUID"),
            ("bc62157e-3e33-4fec-9920-2d3b36d750df",
                "EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID"),
            ("bd8c1056-9f36-44ec-92a8-a6337f817986",
                "EFI_EDID_ACTIVE_PROTOCOL_GUID"),
            ("bdc8e6af-d9bc-4379-a72a-e0c4e75dae1c",
                "EFI_HTTP_SERVICE_BINDING_PROTOCOL_GUID"),
            ("bf0a78ba-ec29-49cf-a1c9-7ae54eab6a51",
                "EFI_MTFTP6_PROTOCOL_GUID"),
            ("c51711e7-b4bf-404a-bfb8-0a048ef1ffe4",
                "EFI_IP4_SERVICE_BINDING_PROTOCOL_GUID"),
            ("c68ed8e2-9dc6-4cbd-9d94-db65acc5c332",
                "EFI_SMM_COMMUNICATION_PROTOCOL_GUID"),
            ("ca37bc1f-a327-4ae9-828a-8c40d8506a17",
                "EFI_DNS6_PROTOCOL_GUID"),
            ("ce345171-ba0b-11d2-8e4f-00a0c969723b",
                "EFI_DISK_IO_PROTOCOL_GUID"),
            ("ce5e5929-c7a3-4602-ad9e-c9daf94ebfcf",
                "EFI_IPSEC_CONFIG_PROTOCOL_GUID"),
            ("d42ae6bd-1352-4bfb-909a-ca72a6eae889",
                "LZMAF86_CUSTOM_DECOMPRESS_GUID"),
            ("d8117cfe-94a6-11d4-9a3a-0090273fc14d",
                "EFI_DECOMPRESS_PROTOCOL_GUID"),
            ("d9760ff3-3cca-4267-80f9-7527fafa4223",
                "EFI_MTFTP6_SERVICE_BINDING_PROTOCOL_GUID"),
            ("db47d7d3-fe81-11d3-9a35-0090273fc14d",
                "EFI_FILE_SYSTEM_VOLUME_LABEL_ID"),
            ("dd9e7534-7762-4698-8c14-f58517a625aa",
                "EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID"),
            ("dfb386f7-e100-43ad-9c9a-ed90d08a5e12",
                "EFI_IPSEC_PROTOCOL_GUID"),
            ("e9ca4775-8657-47fc-97e7-7ed65a084324",
                "EFI_HII_FONT_PROTOCOL_GUID"),
            ("eb338826-681b-4295-b356-2b364c757b09",
                "EFI_FTP4_PROTOCOL_GUID"),
            ("eb9d2d2f-2d88-11d3-9a16-0090273fc14d",
                "MPS_TABLE_GUID"),
            ("eb9d2d30-2d88-11d3-9a16-0090273fc14d",
                "ACPI_TABLE_GUID"),
            ("eb9d2d31-2d88-11d3-9a16-0090273fc14d",
                "SMBIOS_TABLE_GUID"),
            ("eb9d2d32-2d88-11d3-9a16-0090273fc14d",
                "SAL_SYSTEM_TABLE_GUID"),
            ("eba4e8d2-3858-41ec-a281-2647ba9660d0",
                "EFI_DEBUGPORT_PROTOCOL_GUID"),
            ("ec20eb79-6c1a-4664-9a0d-d2e4cc16d664",
                "EFI_TCP6_SERVICE_BINDING_PROTOCOL_GUID"),
            ("ec835dd3-fe0f-617b-a621-b350c3e13388",
                "EFI_IP6_SERVICE_BINDING_PROTOCOL_GUID"),
            ("ee4e5898-3914-4259-9d6e-dc7bd79403cf",
                "LZMA_CUSTOM_DECOMPRESS_GUID"),
            ("ef9fc172-a1b2-4693-b327-6d32fc416042",
                "EFI_HII_DATABASE_PROTOCOL_GUID"),
            ("f2fd1544-9794-4a2c-992e-e5bbcf20e394",
                "SMBIOS3_TABLE_GUID"),
            ("f36ff770-a7e1-42cf-9ed2-56f0f271f44c",
                "EFI_MANAGED_NETWORK_SERVICE_BINDING_PROTOCOL_GUID"),
            ("f44c00ee-1f2c-4a00-aa09-1c9f3e0800a3",
                "EFI_ARP_SERVICE_BINDING_PROTOCOL_GUID"),
            ("f4b427bb-ba21-4f16-bc4e-43e416ab619c",
                "EFI_ARP_PROTOCOL_GUID"),
            ("f4ccbfb7-f6e0-47fd-9dd4-10a8f150c191",
                "EFI_SMM_BASE2_PROTOCOL_GUID"),
            ("f541796d-a62e-4954-a775-9584f61b9cdd",
                "EFI_TCG_PROTOCOL_GUID"),
            ("fc1bcdb0-7d31-49aa-936a-a4600d9dd083",
                "EFI_CRC32_GUIDED_SECTION_EXTRACTION_GUID"),
            ("ffe06bdd-6107-46a6-7bb2-5a9c7ec5275c",
                "EFI_ACPI_TABLE_PROTOCOL_GUID")
        ].into_iter().collect()
    };
}

