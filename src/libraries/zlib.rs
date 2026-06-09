//! NSE zlib library wrapper
//!
//! Zlib compression and decompression library.
//! Based on Nmap's zlib library: https://nmap.org/nsedoc/lib/zlib.html

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use mlua::{Lua, Result as LuaResult, Table, UserData};
use std::io::{Read, Write};

struct DeflateStream {
    buffer: Vec<u8>,
    compressed: Vec<u8>,
    level: Compression,
}

struct InflateStream {
    compressed: Vec<u8>,
    position: usize,
}

impl UserData for DeflateStream {
    fn add_methods<M: mlua::UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("write", |_lua, _self, _data: String| Ok(()));

        methods.add_method("flush", |_lua, _self, ()| Ok(()));

        methods.add_method("close", |_lua, _self, ()| Ok(()));

        methods.add_method("get", |_lua, _self, ()| Ok(b"".to_vec()));
    }
}

impl UserData for InflateStream {
    fn add_methods<M: mlua::UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("lines", |_lua, _self, ()| Ok(Vec::<String>::new()));

        methods.add_method(
            "read",
            |_lua, _self, _how: Option<String>| Ok(String::new()),
        );
    }
}

pub fn register_zlib_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let zlib = lua.create_table()?;

    let adler32_fn = lua.create_function(|_lua, (adler, buffer): (u32, String)| {
        let mut a: u32 = adler;
        for byte in buffer.bytes() {
            a = adler32_loop(a, byte);
        }
        Ok(a)
    })?;
    zlib.set("adler32", adler32_fn)?;

    let crc32_fn = lua.create_function(|_lua, buffer: String| {
        let mut crc: u32 = 0xFFFFFFFF;
        for byte in buffer.bytes() {
            crc = crc32_loop(crc, byte);
        }
        Ok(crc ^ 0xFFFFFFFF)
    })?;
    zlib.set("crc32", crc32_fn)?;

    let compress_fn = lua.create_function(|_lua, (buffer, level): (String, Option<i32>)| {
        let compression_level = match level.unwrap_or(6) {
            0 => Compression::none(),
            1..=3 => Compression::fast(),
            4..=6 => Compression::default(),
            7..=9 => Compression::best(),
            _ => Compression::default(),
        };

        let mut encoder = ZlibEncoder::new(Vec::new(), compression_level);
        encoder
            .write_all(buffer.as_bytes())
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

        Ok(compressed)
    })?;
    zlib.set("compress", compress_fn)?;

    let decompress_fn =
        lua.create_function(|_lua, (buffer, _window_bits): (Vec<u8>, Option<i32>)| {
            let mut decompressed = Vec::new();
            let mut decoder = ZlibDecoder::new(buffer.as_slice());
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            Ok(decompressed)
        })?;
    zlib.set("decompress", decompress_fn)?;

    let deflate_fn = lua.create_function(|lua, (_sink, level): (Table, Option<i32>)| {
        let compression_level = match level.unwrap_or(6) {
            0 => Compression::none(),
            1..=3 => Compression::fast(),
            4..=6 => Compression::default(),
            7..=9 => Compression::best(),
            _ => Compression::default(),
        };

        let stream = DeflateStream {
            buffer: Vec::new(),
            compressed: Vec::new(),
            level: compression_level,
        };

        lua.create_userdata(stream)
    })?;
    zlib.set("deflate", deflate_fn)?;

    let inflate_fn = lua.create_function(|lua, (source, _window_bits): (Table, Option<i32>)| {
        let source_val: String = source.get("data").unwrap_or_default();
        let compressed = source_val.into_bytes();

        let stream = InflateStream {
            compressed,
            position: 0,
        };

        lua.create_userdata(stream)
    })?;
    zlib.set("inflate", inflate_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.2.11"))?;
    zlib.set("version", version_fn)?;

    globals.set("zlib", zlib)?;
    Ok(())
}

fn adler32_loop(a: u32, byte: u8) -> u32 {
    let s1 = (a & 0xFFFF) + byte as u32;
    let s2 = (a >> 16) + (s1 & 0xFFFF);
    ((s1 & 0xFFFF) | (s2 & 0xFFFF) << 16).wrapping_add(s2 >> 16)
}

fn crc32_loop(crc: u32, byte: u8) -> u32 {
    let table = get_crc32_table();
    let index = ((crc ^ byte as u32) & 0xFF) as usize;
    (crc >> 8) ^ table[index]
}

fn get_crc32_table() -> Vec<u32> {
    let mut table = Vec::with_capacity(256);
    for i in 0..256 {
        let mut c = i as u32;
        for _ in 0..8 {
            if c & 1 != 0 {
                c = 0xEDB88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        table.push(c);
    }
    table
}
