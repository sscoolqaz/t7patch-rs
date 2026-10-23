//! Lua symbol recovery for stripped functions and Lua stack traces.
//!
//! Port of `LuaSymbols.cpp`. Two hooks are created:
//! - `HksiLuaGetInfo` restores the name of a `(*stripped)` function when the
//!   live VM state identifies its bytecode in the stock prototype database.
//! - `LuaStateManagerError` rewrites `(*stripped)` frames at the top of the
//!   error object, using the stock database and any `.luacallstackdb` files in
//!   the active mod.
//!
//! The C++ source guards its raw VM reads with MSVC `__try`, which Rust cannot
//! express. Those reads go through `ReadProcessMemory` instead. It reports an
//! unreadable address as a failed read, so malformed VM state falls back to the
//! original behaviour instead of faulting. Symbol files are handled as bytes,
//! as the C++ `std::string` handling does, because they need not be UTF-8.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsString, c_char, c_void};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::os::windows::ffi::OsStringExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use windows::Win32::System::Diagnostics::Debug::{OutputDebugStringA, ReadProcessMemory};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::core::s;

use crate::ffi;
use crate::offsets::{
    self, ACTIVE_MOD_NAME_RVA, HKS_OBJECT_TO_STRING_RVA, HKSI_LUA_GET_INFO_RVA,
    LUA_PUSH_LSTRING_RVA, LUA_STATE_MANAGER_ERROR_RVA,
};

/// Slot index of the Lua stack top (`0x48` bytes into the state, 8-byte slots).
const LUA_STATE_TOP_INDEX: usize = 0x48 / 8;
/// Slot index of the Lua stack base (`0x50` bytes into the state, 8-byte slots).
const LUA_STATE_BASE_INDEX: usize = 0x50 / 8;
const HKS_OBJECT_SIZE: usize = 0x10;
const MAX_MOD_NAME_LENGTH: usize = 64;
const MAX_DATABASE_FILE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_DATABASE_ENTRIES: usize = 1_000_000;
const MAX_STACK_TRACE_SIZE: usize = 1024 * 1024;
const MAX_STOCK_TEXT_LENGTH: usize = 4096;
const MAX_CALL_STACK_LEVEL: usize = 4096;
const CALL_STACK_FRAME_BYTES: usize = 24;
const STOCK_DATABASE_NAME: &str = "t7patch.stockluadb";
const SYMBOL_DATABASE_EXTENSION: &str = "luacallstackdb";

const STATE_CALL_STACK_OFFSET: usize = 0x18;
const STATE_CURRENT_OFFSET: usize = 0x28;
const STATE_BASE_FUNCTION_OFFSET: usize = 0x50;
const DEBUG_NAME_OFFSET: usize = 0x08;
const DEBUG_LEVEL_OFFSET: usize = 0x240;
const DEBUG_TAIL_CALL_OFFSET: usize = 0x244;
const CLOSURE_METHOD_OFFSET: usize = 0x10;
const METHOD_HASH_OFFSET: usize = 0x10;
const METHOD_INSTRUCTION_COUNT_OFFSET: usize = 0x20;
const METHOD_INSTRUCTIONS_OFFSET: usize = 0x28;

/// Value of the first four bytes of a Lua 5.x bytecode chunk (`ESC Lua`).
const LUA_BYTECODE_HEADER: u32 = 0x61754C1B;
/// Name the game gives a function whose debug info was stripped.
const STRIPPED_NAME: &[u8; 12] = b"(*stripped)\0";
/// Text of a stripped frame in a stack trace.
const STRIPPED_FRAME: &[u8] = b"in function '(*stripped)'";

type SymbolMap = HashMap<u64, SymbolRecord>;
type StockSymbolMap = HashMap<u32, StockSymbolRecord>;
type StockPrototypeMap = HashMap<u32, Vec<StockPrototypeRecord>>;

#[derive(Debug, PartialEq, Eq)]
struct SymbolRecord {
    source: Vec<u8>,
    source_line: u32,
    function_name: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct StockSymbolRecord {
    source: Vec<u8>,
    function_name: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct StockPrototypeRecord {
    code_offset: u32,
    function_name: Vec<u8>,
    /// `function_name` cut at its first NUL, owned by the static database so
    /// the game can keep the pointer after the hook returns.
    function_name_c: CString,
}

#[derive(Debug, Default)]
struct StockDatabases {
    symbols: StockSymbolMap,
    prototypes: StockPrototypeMap,
}

/// One accepted line of `t7patch.stockluadb`.
#[derive(Debug)]
struct StockLine {
    function_hash: u32,
    source: Vec<u8>,
    function_name: Vec<u8>,
    code_offset: u32,
}

type LuaStateManagerErrorFn = unsafe extern "system" fn(error: *const c_char, lua_state: *mut i64);
type HksiLuaGetInfoFn = unsafe extern "system" fn(
    lua_state: *mut i64,
    what: *const c_char,
    debug_record: *mut c_void,
) -> i32;
type HksObjectToStringFn = unsafe extern "system" fn(
    lua_state: *mut i64,
    object: i64,
    length: *mut usize,
) -> *const c_char;
type LuaPushLStringFn =
    unsafe extern "system" fn(lua_state: *mut i64, value: *const c_char, length: usize);

static ORIGINAL_LUA_STATE_MANAGER_ERROR: OnceLock<LuaStateManagerErrorFn> = OnceLock::new();
static ORIGINAL_HKSI_LUA_GET_INFO: OnceLock<HksiLuaGetInfoFn> = OnceLock::new();
/// Serialises symbol loading and stack rewriting, as the C++ `SRWLOCK` does.
///
/// `std::sync::Mutex` is exclusive and non-reentrant, like the exclusive
/// SRWLOCK it replaces. It is not literally an SRWLOCK on current Windows
/// builds of std, but the locking behaviour is the same for this use.
static SYMBOL_LOCK: Mutex<()> = Mutex::new(());

/// Abstraction over reads of game memory, so the VM-walking logic can be tested
/// against an in-memory image.
trait Memory {
    /// Copies `buffer.len()` bytes starting at `address`. Returns false if any
    /// byte cannot be read.
    fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> bool;

    fn read_array<const N: usize>(&self, address: usize) -> Option<[u8; N]> {
        let mut buffer = [0u8; N];
        self.read_bytes(address, &mut buffer).then_some(buffer)
    }

    fn read_u32(&self, address: usize) -> Option<u32> {
        self.read_array::<4>(address).map(u32::from_le_bytes)
    }

    fn read_i32(&self, address: usize) -> Option<i32> {
        self.read_array::<4>(address).map(i32::from_le_bytes)
    }

    fn read_usize(&self, address: usize) -> Option<usize> {
        self.read_array::<{ size_of::<usize>() }>(address)
            .map(usize::from_le_bytes)
    }
}

/// Reads the current process through `ReadProcessMemory`, which fails on an
/// unmapped or inaccessible page instead of raising an exception.
struct ProcessMemory;

impl Memory for ProcessMemory {
    fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> bool {
        if address == 0 {
            return false;
        }
        let mut read = 0usize;
        // SAFETY: the process pseudo-handle needs no closing. `buffer` is valid for
        // `buffer.len()` writes, and `read` is a valid out-pointer. A bad source
        // address makes the call return an error rather than fault.
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                ptr::with_exposed_provenance::<c_void>(address),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                Some(&raw mut read),
            )
        }
        .is_ok();
        ok && read == buffer.len()
    }
}

/// Address arithmetic with the wrapping behaviour of the C++ `uintptr_t` math.
const fn at(base: usize, offset: usize) -> usize {
    base.wrapping_add(offset)
}

/// Reinterprets a `MinHook` trampoline address as the function pointer type `F`.
///
/// # Safety
///
/// `address` must be a trampoline or entry point whose signature is `F`.
unsafe fn trampoline<F: Copy>(address: usize) -> F {
    const { assert!(size_of::<F>() == size_of::<usize>()) };
    // SAFETY: the caller guarantees `address` holds a function pointer of type `F`.
    unsafe { std::mem::transmute_copy(&address) }
}

fn make_symbol_key(function_hash: u32, instruction_index: u32) -> u64 {
    (u64::from(function_hash) << 32) | u64::from(instruction_index)
}

/// Splits a symbol key into `(function hash, instruction index)`.
fn split_symbol_key(key: u64) -> (u32, u32) {
    let function_hash = u32::try_from(key >> 32).unwrap_or_default();
    let instruction_index = u32::try_from(key & 0xFFFF_FFFF).unwrap_or_default();
    (function_hash, instruction_index)
}

/// Parses an unsigned decimal the way `std::from_chars` does: digits only, no
/// sign or whitespace, and no overflow.
fn parse_u32(value: &[u8]) -> Option<u32> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0u32, |accumulated, &byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        accumulated
            .checked_mul(10)?
            .checked_add(u32::from(byte - b'0'))
    })
}

fn find_byte(haystack: &[u8], from: usize, needle: u8) -> Option<usize> {
    haystack
        .get(from..)?
        .iter()
        .position(|&byte| byte == needle)
        .map(|offset| from + offset)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Strips a leading `@` and turns Windows path separators into `/`.
fn display_source(mut source: Vec<u8>) -> Vec<u8> {
    if source.first() == Some(&b'@') {
        source.remove(0);
    }
    for byte in &mut source {
        if *byte == b'\\' {
            *byte = b'/';
        }
    }
    source
}

/// Yields the lines of a reader as bytes, without the trailing `\n`.
///
/// Matches `std::getline`: the final line may lack a newline, and a read error
/// ends the stream.
struct ByteLines<R>(R);

impl<R: BufRead> Iterator for ByteLines<R> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let mut line = Vec::new();
        match self.0.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => {
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                Some(line)
            }
        }
    }
}

/// Accepts a mod name made of ASCII letters, digits, `_` and `-`, shorter than
/// `MAX_MOD_NAME_LENGTH`.
fn is_safe_mod_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() < MAX_MOD_NAME_LENGTH
        && name
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn active_mod_name(raw: &[u8]) -> Option<String> {
    if is_safe_mod_name(raw) {
        String::from_utf8(raw.to_vec()).ok()
    } else {
        None
    }
}

fn read_active_mod_name() -> Option<String> {
    let memory = ProcessMemory;
    let address = offsets::address(ACTIVE_MOD_NAME_RVA);
    let mut name = Vec::new();
    // Stops at the NUL terminator, like `strnlen_s` with a 64-byte limit.
    for offset in 0..MAX_MOD_NAME_LENGTH {
        let mut byte = [0u8];
        if !memory.read_bytes(at(address, offset), &mut byte) || byte[0] == 0 {
            break;
        }
        name.push(byte[0]);
    }
    active_mod_name(&name)
}

/// Directory holding the executable, or an empty path if it cannot be queried.
fn game_directory() -> PathBuf {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: a null module handle names the calling process's executable. `buffer`
    // is valid for `buffer.len()` UTF-16 units.
    let length = unsafe { GetModuleFileNameW(None, &mut buffer) } as usize;
    if length == 0 || length >= buffer.len() {
        return PathBuf::new();
    }
    buffer.truncate(length);
    PathBuf::from(OsString::from_wide(&buffer))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

fn mod_directory(game_directory: &Path, mod_name: &str) -> PathBuf {
    game_directory.join("mods").join(mod_name)
}

/// True for a file whose extension is `.luacallstackdb`, ignoring ASCII case.
fn is_symbol_database(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(SYMBOL_DATABASE_EXTENSION))
}

/// Opens a database file if it is a non-empty regular file within the size cap.
fn open_database(path: &Path) -> Option<BufReader<File>> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_DATABASE_FILE_SIZE {
        return None;
    }
    Some(BufReader::new(File::open(path).ok()?))
}

/// Parses one `hash,instruction,source,line,function` row. Commas after the
/// fourth are part of the function name.
fn parse_symbol_line(line: &[u8]) -> Option<(u64, SymbolRecord)> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);

    let mut commas = [0usize; 4];
    let mut search_from = 0;
    for comma in &mut commas {
        *comma = find_byte(line, search_from, b',')?;
        search_from = *comma + 1;
    }

    let function_hash = parse_u32(&line[..commas[0]])?;
    let instruction_index = parse_u32(&line[commas[0] + 1..commas[1]])?;
    let source_line = parse_u32(&line[commas[2] + 1..commas[3]])?;
    let source = display_source(line[commas[1] + 1..commas[2]].to_vec());
    if source.is_empty() {
        return None;
    }

    Some((
        make_symbol_key(function_hash, instruction_index),
        SymbolRecord {
            source,
            source_line,
            function_name: line[commas[3] + 1..].to_vec(),
        },
    ))
}

/// Merges one symbol database into `symbols`. A key that maps to two different
/// records in any file is dropped and remembered as ambiguous.
fn load_symbol_database(
    reader: impl BufRead,
    symbols: &mut SymbolMap,
    ambiguous_keys: &mut HashSet<u64>,
) {
    for line in ByteLines(reader) {
        if symbols.len() >= MAX_DATABASE_ENTRIES {
            break;
        }
        let Some((key, record)) = parse_symbol_line(&line) else {
            continue;
        };
        if ambiguous_keys.contains(&key) {
            continue;
        }
        match symbols.entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(record);
            }
            Entry::Occupied(slot) => {
                if *slot.get() != record {
                    slot.remove();
                    ambiguous_keys.insert(key);
                }
            }
        }
    }
}

/// Iterates the files under a directory tree, depth first.
///
/// Symbolic links to directories are not followed, as with
/// `recursive_directory_iterator`. Permission errors skip the entry. Any other
/// error ends the walk.
struct RecursiveFiles {
    stack: Vec<fs::ReadDir>,
}

impl RecursiveFiles {
    fn new(root: &Path) -> Self {
        Self {
            stack: fs::read_dir(root).ok().into_iter().collect(),
        }
    }
}

impl Iterator for RecursiveFiles {
    type Item = PathBuf;

    fn next(&mut self) -> Option<PathBuf> {
        loop {
            let entries = self.stack.last_mut()?;
            let entry = match entries.next() {
                None => {
                    self.stack.pop();
                    continue;
                }
                Some(Ok(entry)) => entry,
                Some(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied => continue,
                Some(Err(_)) => {
                    self.stack.clear();
                    return None;
                }
            };
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                match fs::read_dir(&path) {
                    Ok(children) => self.stack.push(children),
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
                    Err(_) => {
                        self.stack.clear();
                        return None;
                    }
                }
                continue;
            }
            return Some(path);
        }
    }
}

/// Loads every `.luacallstackdb` under the active mod's directory.
fn load_symbols_for_active_mod() -> SymbolMap {
    let mut symbols = SymbolMap::new();
    let Some(mod_name) = read_active_mod_name() else {
        return symbols;
    };
    let game_directory = game_directory();
    if game_directory.as_os_str().is_empty() {
        return symbols;
    }

    let directory = mod_directory(&game_directory, &mod_name);
    if !fs::metadata(&directory).is_ok_and(|metadata| metadata.is_dir()) {
        return symbols;
    }

    let mut ambiguous_keys = HashSet::new();
    let mut files = RecursiveFiles::new(&directory);
    while symbols.len() < MAX_DATABASE_ENTRIES {
        let Some(path) = files.next() else {
            break;
        };
        if !is_symbol_database(&path) {
            continue;
        }
        if let Some(reader) = open_database(&path) {
            load_symbol_database(reader, &mut symbols, &mut ambiguous_keys);
        }
    }
    symbols
}

/// Parses one `t7patch.stockluadb` row. Three layouts are accepted:
/// - version 1: `hash,source`
/// - version 2: `hash,source,function`
/// - version 3: `hash,source,code_offset,function`
///
/// Comment lines start with `#`.
fn parse_stock_line(line: &[u8]) -> Option<StockLine> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.first().is_none_or(|&byte| byte == b'#') {
        return None;
    }

    let first_comma = find_byte(line, 0, b',')?;
    if first_comma == 0 || first_comma + 1 >= line.len() {
        return None;
    }
    let function_hash = parse_u32(&line[..first_comma])?;
    if function_hash == 0 {
        return None;
    }

    let second_comma = find_byte(line, first_comma + 1, b',');
    let source_end = second_comma.unwrap_or(line.len());
    let source = display_source(line[first_comma + 1..source_end].to_vec());
    if source.is_empty() || source.len() > MAX_STOCK_TEXT_LENGTH {
        return None;
    }

    let mut code_offset = 0;
    let mut function_name = Vec::new();
    if let Some(second) = second_comma {
        let prototype = find_byte(line, second + 1, b',').and_then(|third| {
            let offset = parse_u32(&line[second + 1..third])?;
            Some((third, offset))
        });
        match prototype {
            Some((third, offset)) => {
                code_offset = offset;
                function_name = line[third + 1..].to_vec();
            }
            // Version 2 stored the name directly after the source path.
            None => function_name = line[second + 1..].to_vec(),
        }
    }
    if function_name.len() > MAX_STOCK_TEXT_LENGTH {
        return None;
    }

    Some(StockLine {
        function_hash,
        source,
        function_name,
        code_offset,
    })
}

fn c_name(name: &[u8]) -> CString {
    let end = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(name.len());
    CString::new(&name[..end]).unwrap_or_default()
}

/// Adds one stock row, marking the hash ambiguous when two sources share it.
fn merge_stock_line(
    databases: &mut StockDatabases,
    ambiguous_hashes: &mut HashSet<u32>,
    line: StockLine,
) {
    let hash = line.function_hash;
    if line.code_offset != 0 && !line.function_name.is_empty() {
        databases
            .prototypes
            .entry(hash)
            .or_default()
            .push(StockPrototypeRecord {
                code_offset: line.code_offset,
                function_name_c: c_name(&line.function_name),
                function_name: line.function_name.clone(),
            });
    }

    match databases.symbols.entry(hash) {
        Entry::Vacant(slot) => {
            slot.insert(StockSymbolRecord {
                source: line.source,
                function_name: line.function_name,
            });
        }
        Entry::Occupied(mut slot) => {
            if slot.get().source != line.source {
                slot.remove();
                databases.prototypes.remove(&hash);
                ambiguous_hashes.insert(hash);
            } else if slot.get().function_name != line.function_name {
                // The hash identifies this source but more than one closure
                // shares it. Live prototype matching may still recover the
                // exact name; the text-only fallback may not.
                slot.get_mut().function_name.clear();
            }
        }
    }
}

fn parse_stock_database(reader: impl BufRead) -> StockDatabases {
    let mut databases = StockDatabases::default();
    let mut ambiguous_hashes = HashSet::new();
    let mut entries = 0usize;
    for line in ByteLines(reader) {
        if entries >= MAX_DATABASE_ENTRIES {
            break;
        }
        let Some(record) = parse_stock_line(&line) else {
            continue;
        };
        if ambiguous_hashes.contains(&record.function_hash) {
            continue;
        }
        merge_stock_line(&mut databases, &mut ambiguous_hashes, record);
        entries += 1;
    }
    databases
}

fn load_stock_databases() -> StockDatabases {
    let game_directory = game_directory();
    if game_directory.as_os_str().is_empty() {
        return StockDatabases::default();
    }
    match open_database(&game_directory.join(STOCK_DATABASE_NAME)) {
        Some(reader) => parse_stock_database(reader),
        None => StockDatabases::default(),
    }
}

fn stock_databases() -> &'static StockDatabases {
    static DATABASES: OnceLock<StockDatabases> = OnceLock::new();
    DATABASES.get_or_init(load_stock_databases)
}

/// Recovers `(function hash, instruction array address)` for a stripped frame
/// from the live Lua VM state. Returns `None` on any inconsistency.
fn live_prototype(
    memory: &impl Memory,
    lua_state: usize,
    debug_record: usize,
) -> Option<(u32, usize)> {
    if lua_state == 0 || debug_record == 0 {
        return None;
    }

    let records = memory.read_usize(at(lua_state, STATE_CALL_STACK_OFFSET))?;
    let current = memory.read_usize(at(lua_state, STATE_CURRENT_OFFSET))?;
    let level = memory.read_i32(at(debug_record, DEBUG_LEVEL_OFFSET))?;
    let is_tail_call = memory.read_i32(at(debug_record, DEBUG_TAIL_CALL_OFFSET))?;

    let level = usize::try_from(level).ok()?;
    if records == 0 || current < records || is_tail_call != 0 {
        return None;
    }

    let call_stack_bytes = current - records;
    if !call_stack_bytes.is_multiple_of(CALL_STACK_FRAME_BYTES) {
        return None;
    }
    let current_level = call_stack_bytes / CALL_STACK_FRAME_BYTES;
    if current_level > MAX_CALL_STACK_LEVEL || level > current_level {
        return None;
    }

    let function_base = if level == current_level {
        memory.read_usize(at(lua_state, STATE_BASE_FUNCTION_OFFSET))?
    } else {
        memory.read_usize(at(records, CALL_STACK_FRAME_BYTES * (level + 1)))?
    };
    if function_base < HKS_OBJECT_SIZE {
        return None;
    }

    let type_bits = memory.read_usize(function_base - HKS_OBJECT_SIZE)?;
    if (type_bits & 0xF) != 9 {
        return None;
    }
    let closure = memory.read_usize(function_base - size_of::<usize>())?;
    if closure == 0 {
        return None;
    }

    let method = memory.read_usize(at(closure, CLOSURE_METHOD_OFFSET))?;
    if method == 0 {
        return None;
    }
    let instruction_count = memory.read_u32(at(method, METHOD_INSTRUCTION_COUNT_OFFSET))?;
    let instructions = memory.read_usize(at(method, METHOD_INSTRUCTIONS_OFFSET))?;
    let hash = memory.read_u32(at(method, METHOD_HASH_OFFSET))?;
    if hash == 0
        || instructions == 0
        || instruction_count == 0
        || instruction_count as usize > MAX_DATABASE_ENTRIES
    {
        return None;
    }
    Some((hash, instructions))
}

fn has_bytecode_header(memory: &impl Memory, address: usize) -> bool {
    address != 0 && memory.read_u32(address) == Some(LUA_BYTECODE_HEADER)
}

/// Finds the stock prototype whose bytecode header sits right before the live
/// instruction array. Two different candidates that both match make the result
/// unknown.
fn resolve_live_function_name<'a>(
    memory: &impl Memory,
    databases: &'a StockDatabases,
    function_hash: u32,
    instructions: usize,
) -> Option<&'a CStr> {
    let candidates = databases.prototypes.get(&function_hash)?;
    let mut matched: Option<&StockPrototypeRecord> = None;
    for candidate in candidates {
        let code_offset = candidate.code_offset as usize;
        if u64::from(candidate.code_offset) > MAX_DATABASE_FILE_SIZE || instructions < code_offset {
            continue;
        }
        if !has_bytecode_header(memory, instructions - code_offset) {
            continue;
        }
        if let Some(previous) = matched {
            if previous.code_offset != candidate.code_offset
                || previous.function_name != candidate.function_name
            {
                return None;
            }
        }
        matched = Some(candidate);
    }
    matched
        .filter(|found| !found.function_name.is_empty())
        .map(|found| found.function_name_c.as_c_str())
}

fn is_stripped_name(memory: &impl Memory, address: usize) -> bool {
    memory.read_array::<12>(address) == Some(*STRIPPED_NAME)
}

/// Parses a `[spaces]hash:index:` frame prefix. Returns the start of the
/// prefix, the end just past the second colon, and the symbol key.
fn parse_frame_prefix(line: &[u8]) -> Option<(usize, usize, u64)> {
    let start = line
        .iter()
        .position(|&byte| byte != b' ' && byte != b'\t')
        .unwrap_or(line.len());

    let mut cursor = start;
    while cursor < line.len() && line[cursor].is_ascii_digit() {
        cursor += 1;
    }
    if cursor == start || cursor >= line.len() || line[cursor] != b':' {
        return None;
    }
    let function_hash = parse_u32(&line[start..cursor])?;

    let instruction_start = cursor + 1;
    cursor = instruction_start;
    while cursor < line.len() && line[cursor].is_ascii_digit() {
        cursor += 1;
    }
    if cursor == instruction_start || cursor >= line.len() || line[cursor] != b':' {
        return None;
    }
    let instruction_index = parse_u32(&line[instruction_start..cursor])?;

    Some((
        start,
        cursor + 1,
        make_symbol_key(function_hash, instruction_index),
    ))
}

/// Appends the rest of a frame, replacing `(*stripped)` with the function name
/// when one is known.
fn append_frame_tail(output: &mut Vec<u8>, remainder: &[u8], function_name: &[u8]) {
    match find_subslice(remainder, STRIPPED_FRAME) {
        Some(stripped) if !function_name.is_empty() => {
            output.extend_from_slice(&remainder[..stripped]);
            output.extend_from_slice(b"in function '");
            output.extend_from_slice(function_name);
            output.push(b'\'');
            output.extend_from_slice(&remainder[stripped + STRIPPED_FRAME.len()..]);
        }
        _ => output.extend_from_slice(remainder),
    }
}

/// Rewrites every frame that has a symbol. Returns the new trace and the number
/// of frames changed. An empty trace means the output would exceed the size cap.
fn rewrite_stack_trace(
    stack_trace: &[u8],
    symbols: &SymbolMap,
    stock_symbols: &StockSymbolMap,
) -> (Vec<u8>, usize) {
    let mut rewritten = Vec::with_capacity(stack_trace.len());
    let mut resolved_frames = 0usize;
    let mut position = 0usize;

    while position < stack_trace.len() {
        let newline = find_byte(stack_trace, position, b'\n');
        let line_end = newline.unwrap_or(stack_trace.len());
        let line = &stack_trace[position..line_end];

        let prefix = parse_frame_prefix(line);
        let symbol = prefix.and_then(|(_, _, key)| symbols.get(&key));
        let stock_symbol = match (prefix, symbol) {
            (Some((_, _, key)), None) => stock_symbols.get(&split_symbol_key(key).0),
            _ => None,
        };

        match (prefix, symbol, stock_symbol) {
            (Some((start, end, _)), Some(record), _) => {
                rewritten.extend_from_slice(&line[..start]);
                rewritten.extend_from_slice(&record.source);
                rewritten.push(b':');
                rewritten.extend_from_slice(record.source_line.to_string().as_bytes());
                rewritten.push(b':');
                append_frame_tail(&mut rewritten, &line[end..], &record.function_name);
                resolved_frames += 1;
            }
            (Some((start, end, key)), None, Some(record)) => {
                rewritten.extend_from_slice(&line[..start]);
                rewritten.extend_from_slice(&record.source);
                rewritten.extend_from_slice(b":pc");
                rewritten.extend_from_slice(split_symbol_key(key).1.to_string().as_bytes());
                rewritten.push(b':');
                append_frame_tail(&mut rewritten, &line[end..], &record.function_name);
                resolved_frames += 1;
            }
            _ => rewritten.extend_from_slice(line),
        }

        let Some(newline) = newline else {
            break;
        };
        rewritten.push(b'\n');
        position = newline + 1;

        if rewritten.len() > MAX_STACK_TRACE_SIZE {
            return (Vec::new(), resolved_frames);
        }
    }
    (rewritten, resolved_frames)
}

fn lock_symbols() -> MutexGuard<'static, ()> {
    SYMBOL_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads the Lua stack top and base, and checks that the top holds an object.
///
/// # Safety
///
/// `lua_state` must point to a live Lua state.
unsafe fn stack_bounds(lua_state: *mut i64) -> Option<(usize, usize)> {
    // SAFETY: the caller guarantees a live state, and both slots lie inside its header.
    let (top, base) = unsafe {
        (
            *lua_state.add(LUA_STATE_TOP_INDEX),
            *lua_state.add(LUA_STATE_BASE_INDEX),
        )
    };
    let top = usize::try_from(top).ok()?;
    let base = usize::try_from(base).ok()?;
    if top < base.checked_add(HKS_OBJECT_SIZE)? || top - base > MAX_STACK_TRACE_SIZE {
        return None;
    }
    Some((top, base))
}

/// Pushes `rewritten` as a new string and swaps it into the slot of the old
/// error object. Returns false and restores the top if the push misbehaves.
///
/// # Safety
///
/// `lua_state` must point to a live Lua state whose stack top holds an object.
unsafe fn replace_top_error_object(lua_state: *mut i64, rewritten: &[u8]) -> bool {
    if rewritten.is_empty() || rewritten.len() > MAX_STACK_TRACE_SIZE {
        return false;
    }
    // SAFETY: the caller guarantees a live state.
    let Some((top, _)) = (unsafe { stack_bounds(lua_state) }) else {
        return false;
    };
    let Ok(top_slot) = i64::try_from(top) else {
        return false;
    };

    // SAFETY: the offset comes from the game image's build table, and the signature matches
    // the February 2026 `lua_pushlstring`.
    let push_string: LuaPushLStringFn = unsafe { offsets::function(LUA_PUSH_LSTRING_RVA) };
    // SAFETY: the callee copies `rewritten.len()` bytes from a valid buffer onto the live state.
    unsafe { push_string(lua_state, rewritten.as_ptr().cast(), rewritten.len()) };

    // SAFETY: the state is still live, and this reads its top slot.
    let new_top = unsafe { *lua_state.add(LUA_STATE_TOP_INDEX) };
    if Some(new_top) != i64::try_from(top + HKS_OBJECT_SIZE).ok() {
        // SAFETY: restores the top slot this function read above.
        unsafe { *lua_state.add(LUA_STATE_TOP_INDEX) = top_slot };
        return false;
    }

    // SAFETY: the pushed object is at `top` and the old error object is at `top - 16`.
    // Each is one 16-byte value, and the two ranges do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::with_exposed_provenance::<u8>(top),
            ptr::with_exposed_provenance_mut::<u8>(top - HKS_OBJECT_SIZE),
            HKS_OBJECT_SIZE,
        );
        *lua_state.add(LUA_STATE_TOP_INDEX) = top_slot;
    }
    true
}

/// Rewrites the stack trace at the top of the Lua error object, if it has any
/// stripped frames that can be named.
///
/// # Safety
///
/// `lua_state` must be the live state the game passed to `LuaStateManagerError`.
unsafe fn resolve_top_error_stack(lua_state: *mut i64) {
    if lua_state.is_null() {
        return;
    }
    // SAFETY: the caller guarantees a live state.
    let Some((top, _)) = (unsafe { stack_bounds(lua_state) }) else {
        return;
    };
    let Ok(object) = i64::try_from(top - HKS_OBJECT_SIZE) else {
        return;
    };

    // SAFETY: the offset comes from the game image's build table, and the signature matches
    // the February 2026 `HksObjectToString`.
    let object_to_string: HksObjectToStringFn =
        unsafe { offsets::function(HKS_OBJECT_TO_STRING_RVA) };
    let mut length = 0usize;
    // SAFETY: `object` is the object at the top of the live state's stack, and `length`
    // is a valid out-pointer.
    let stack = unsafe { object_to_string(lua_state, object, &raw mut length) };
    if stack.is_null() || length == 0 || length > MAX_STACK_TRACE_SIZE {
        return;
    }
    // SAFETY: a successful conversion returns `length` readable bytes. They are copied
    // before any further Lua call can move them.
    let original = unsafe { std::slice::from_raw_parts(stack.cast::<u8>(), length) }.to_vec();

    let _guard = lock_symbols();
    let symbols = load_symbols_for_active_mod();
    let (rewritten, resolved_frames) =
        rewrite_stack_trace(&original, &symbols, &stock_databases().symbols);
    if resolved_frames != 0 && !rewritten.is_empty() && rewritten != original {
        // SAFETY: the state is still live, and no Lua call has happened since `stack_bounds`.
        if unsafe { replace_top_error_object(lua_state, &rewritten) } {
            // SAFETY: the message is a static NUL-terminated string.
            unsafe { OutputDebugStringA(s!("T7 Patch: resolved Lua stack symbols.\n")) };
        }
    }
}

/// Detour for `HksiLuaGetInfo`. Restores the name of a stripped function.
unsafe extern "system" fn hksi_lua_get_info_hook(
    lua_state: *mut i64,
    what: *const c_char,
    debug_record: *mut c_void,
) -> i32 {
    let Some(original) = ORIGINAL_HKSI_LUA_GET_INFO.get().copied() else {
        return 0;
    };
    // SAFETY: forwards the game's own arguments to the original function.
    let result = unsafe { original(lua_state, what, debug_record) };
    if result == 0 || debug_record.is_null() {
        return result;
    }

    let debug = debug_record.addr();
    let memory = ProcessMemory;
    let Some(name) = memory.read_usize(at(debug, DEBUG_NAME_OFFSET)) else {
        return result;
    };
    if !is_stripped_name(&memory, name) {
        return result;
    }
    let Some((function_hash, instructions)) = live_prototype(&memory, lua_state.addr(), debug)
    else {
        return result;
    };
    if let Some(resolved) =
        resolve_live_function_name(&memory, stock_databases(), function_hash, instructions)
    {
        // SAFETY: the name slot of the game's debug record is writable, as the C++ source
        // writes it directly. The string lives in the static stock database, so the
        // pointer stays valid after this hook returns.
        unsafe {
            ptr::write(
                ptr::with_exposed_provenance_mut::<*const c_char>(at(debug, DEBUG_NAME_OFFSET)),
                resolved.as_ptr(),
            );
        }
    }
    result
}

/// Detour for `LuaStateManagerError`. Rewrites stack symbols, then calls the
/// original. A panic in the rewrite is caught so the original error still runs.
unsafe extern "system" fn lua_state_manager_error_hook(error: *const c_char, lua_state: *mut i64) {
    let resolved = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the game passes `lua_state` to this hook as a live state.
        unsafe { resolve_top_error_stack(lua_state) };
    }));
    if resolved.is_err() {
        // SAFETY: the message is a static NUL-terminated string.
        unsafe {
            OutputDebugStringA(s!(
                "T7 Patch: Lua symbol resolution failed; using the original stack trace.\n"
            ));
        }
    }
    if let Some(original) = ORIGINAL_LUA_STATE_MANAGER_ERROR.get() {
        // SAFETY: forwards the game's own arguments to the original function.
        unsafe { original(error, lua_state) };
    }
}

/// Creates the `HksiLuaGetInfo` and `LuaStateManagerError` hooks.
///
/// Port of `lua_symbols::InstallHooks`. As in the C++ source, the hooks are
/// created but not enabled here, and a failed create is ignored. In that case the
/// original stays unset and the detour is never reached.
pub fn install_hooks() {
    // SAFETY: the target is the HksiLuaGetInfo entry point of the running build. The
    // detour has the same signature.
    if let Ok(original) = unsafe {
        ffi::create_hook(
            offsets::address(HKSI_LUA_GET_INFO_RVA),
            hksi_lua_get_info_hook as HksiLuaGetInfoFn as usize,
        )
    } {
        // SAFETY: `original` is the MinHook trampoline for HksiLuaGetInfo, which has
        // the `HksiLuaGetInfoFn` signature.
        let _ = ORIGINAL_HKSI_LUA_GET_INFO.set(unsafe { trampoline(original) });
    }

    // SAFETY: the target is the LuaStateManagerError entry point of the running build. The
    // detour has the same signature.
    if let Ok(original) = unsafe {
        ffi::create_hook(
            offsets::address(LUA_STATE_MANAGER_ERROR_RVA),
            lua_state_manager_error_hook as LuaStateManagerErrorFn as usize,
        )
    } {
        // SAFETY: `original` is the MinHook trampoline for LuaStateManagerError, which has
        // the `LuaStateManagerErrorFn` signature.
        let _ = ORIGINAL_LUA_STATE_MANAGER_ERROR.set(unsafe { trampoline(original) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory stand-in for game memory.
    #[derive(Default)]
    struct FakeMemory {
        bytes: HashMap<usize, u8>,
    }

    impl FakeMemory {
        fn write(&mut self, address: usize, data: &[u8]) {
            for (offset, byte) in data.iter().enumerate() {
                self.bytes.insert(address + offset, *byte);
            }
        }

        fn write_usize(&mut self, address: usize, value: usize) {
            self.write(address, &value.to_le_bytes());
        }

        fn write_u32(&mut self, address: usize, value: u32) {
            self.write(address, &value.to_le_bytes());
        }

        fn write_i32(&mut self, address: usize, value: i32) {
            self.write(address, &value.to_le_bytes());
        }
    }

    impl Memory for FakeMemory {
        fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> bool {
            for (offset, slot) in buffer.iter_mut().enumerate() {
                let Some(byte) = self.bytes.get(&(address + offset)) else {
                    return false;
                };
                *slot = *byte;
            }
            true
        }
    }

    const STATE: usize = 0x1000;
    const DEBUG: usize = 0x2000;
    const RECORDS: usize = 0x3000;
    const FUNCTION: usize = 0x5000;
    const CLOSURE: usize = 0x6000;
    const METHOD: usize = 0x7000;
    const INSTRUCTIONS: usize = 0x8000;
    const HASH: u32 = 0xABCD;

    /// A Lua state with two call frames, the top one at `level` 2.
    fn live_fixture() -> FakeMemory {
        let mut memory = FakeMemory::default();
        memory.write_usize(STATE + STATE_CALL_STACK_OFFSET, RECORDS);
        memory.write_usize(STATE + STATE_CURRENT_OFFSET, RECORDS + 24 * 2);
        memory.write_usize(STATE + STATE_BASE_FUNCTION_OFFSET, FUNCTION);
        memory.write_i32(DEBUG + DEBUG_LEVEL_OFFSET, 2);
        memory.write_i32(DEBUG + DEBUG_TAIL_CALL_OFFSET, 0);
        memory.write_usize(RECORDS + 24, FUNCTION);
        memory.write_usize(FUNCTION - HKS_OBJECT_SIZE, 9);
        memory.write_usize(FUNCTION - size_of::<usize>(), CLOSURE);
        memory.write_usize(CLOSURE + CLOSURE_METHOD_OFFSET, METHOD);
        memory.write_u32(METHOD + METHOD_HASH_OFFSET, HASH);
        memory.write_u32(METHOD + METHOD_INSTRUCTION_COUNT_OFFSET, 3);
        memory.write_usize(METHOD + METHOD_INSTRUCTIONS_OFFSET, INSTRUCTIONS);
        memory
    }

    #[test]
    fn parse_u32_matches_from_chars_rules() {
        assert_eq!(parse_u32(b"0"), Some(0));
        assert_eq!(parse_u32(b"007"), Some(7));
        assert_eq!(parse_u32(b"4294967295"), Some(u32::MAX));
        assert_eq!(parse_u32(b"4294967296"), None);
        assert_eq!(parse_u32(b"+1"), None);
        assert_eq!(parse_u32(b"-1"), None);
        assert_eq!(parse_u32(b" 1"), None);
        assert_eq!(parse_u32(b"1 "), None);
        assert_eq!(parse_u32(b""), None);
    }

    #[test]
    fn symbol_key_packs_hash_high_and_index_low() {
        assert_eq!(make_symbol_key(0x1234, 5), 0x0000_1234_0000_0005);
        assert_eq!(make_symbol_key(u32::MAX, u32::MAX), u64::MAX);
    }

    #[test]
    fn display_source_strips_one_at_and_flips_separators() {
        assert_eq!(
            display_source(b"@scripts\\a.gsc".to_vec()),
            b"scripts/a.gsc"
        );
        assert_eq!(display_source(b"@@x".to_vec()), b"@x");
        assert_eq!(display_source(b"a\\b\\c".to_vec()), b"a/b/c");
        assert_eq!(display_source(Vec::new()), b"");
    }

    #[test]
    fn symbol_line_parses_and_keeps_commas_in_name() {
        let (key, record) =
            parse_symbol_line(b"1234,5,@scripts\\a.gsc,42,fn,with,commas\r").unwrap();
        assert_eq!(key, make_symbol_key(1234, 5));
        assert_eq!(record.source, b"scripts/a.gsc");
        assert_eq!(record.source_line, 42);
        assert_eq!(record.function_name, b"fn,with,commas");
    }

    #[test]
    fn symbol_line_rejects_bad_rows() {
        assert!(
            parse_symbol_line(b"1,2,a.gsc,3").is_none(),
            "needs four commas"
        );
        assert!(parse_symbol_line(b"x,2,a.gsc,3,f").is_none(), "bad hash");
        assert!(parse_symbol_line(b"1,2,a.gsc,-3,f").is_none(), "bad line");
        assert!(parse_symbol_line(b"1,2,,3,f").is_none(), "empty source");
    }

    #[test]
    fn mod_names_follow_the_safe_character_rules() {
        assert!(is_safe_mod_name(b"my-mod_1"));
        assert!(is_safe_mod_name(&[b'a'; 63]));
        assert!(!is_safe_mod_name(&[b'a'; 64]));
        assert!(!is_safe_mod_name(b""));
        assert!(!is_safe_mod_name(b"a.b"));
        assert!(!is_safe_mod_name(b"a b"));
        assert!(!is_safe_mod_name(b"..\\x"));
        assert_eq!(active_mod_name(b"ok"), Some("ok".to_owned()));
        assert_eq!(active_mod_name(b"no good"), None);
    }

    #[test]
    fn symbol_database_extension_ignores_case() {
        assert!(is_symbol_database(Path::new("x/y.LuaCallStackDB")));
        assert!(is_symbol_database(Path::new("y.luacallstackdb")));
        assert!(!is_symbol_database(Path::new("x/y.lua")));
        assert!(!is_symbol_database(Path::new(".luacallstackdb")));
    }

    #[test]
    fn mod_directory_sits_under_mods() {
        assert_eq!(
            mod_directory(Path::new("C:/Game"), "my-mod"),
            Path::new("C:/Game/mods/my-mod")
        );
        assert_eq!(STOCK_DATABASE_NAME, "t7patch.stockluadb");
    }

    #[test]
    fn symbol_database_keeps_agreeing_duplicates_and_drops_conflicts() {
        let data = b"1,2,a.gsc,3,f\n1,2,a.gsc,3,f\n5,6,b.gsc,7,g";
        let mut symbols = SymbolMap::new();
        let mut ambiguous = HashSet::new();
        load_symbol_database(&data[..], &mut symbols, &mut ambiguous);
        assert_eq!(symbols.len(), 2);
        assert!(ambiguous.is_empty());
        assert_eq!(symbols[&make_symbol_key(5, 6)].function_name, b"g");

        let conflict = b"1,2,a.gsc,3,f\n1,2,a.gsc,4,f\n1,2,a.gsc,3,f\n";
        let mut symbols = SymbolMap::new();
        let mut ambiguous = HashSet::new();
        load_symbol_database(&conflict[..], &mut symbols, &mut ambiguous);
        assert!(!symbols.contains_key(&make_symbol_key(1, 2)));
        assert!(ambiguous.contains(&make_symbol_key(1, 2)));
    }

    #[test]
    fn stock_database_reads_all_three_layouts() {
        let text = b"# comment\r\n\
            1234,@scripts\\a.gsc\r\n\
            5678,a.gsc,fn_v2\n\
            9012,b.gsc,16,fn_v3\n\
            0,c.gsc,fn\n\
            42,\n";
        let databases = parse_stock_database(&text[..]);
        assert_eq!(databases.symbols[&1234].source, b"scripts/a.gsc");
        assert!(databases.symbols[&1234].function_name.is_empty());
        assert_eq!(databases.symbols[&5678].function_name, b"fn_v2");
        assert_eq!(databases.symbols[&9012].function_name, b"fn_v3");
        assert_eq!(databases.prototypes[&9012][0].code_offset, 16);
        assert!(!databases.symbols.contains_key(&0));
        assert!(!databases.symbols.contains_key(&42));
    }

    #[test]
    fn stock_database_clears_name_on_closure_conflict() {
        let text = b"5678,a.gsc,fn_v2\n5678,a.gsc,fn_other\n";
        let databases = parse_stock_database(&text[..]);
        assert_eq!(databases.symbols[&5678].source, b"a.gsc");
        assert!(databases.symbols[&5678].function_name.is_empty());
    }

    #[test]
    fn stock_database_drops_hash_on_source_conflict() {
        let text = b"7,a.gsc,16,f1\n7,b.gsc,16,f1\n";
        let databases = parse_stock_database(&text[..]);
        assert!(!databases.symbols.contains_key(&7));
        assert!(!databases.prototypes.contains_key(&7));
    }

    #[test]
    fn frame_prefix_parses_hash_and_index() {
        assert_eq!(
            parse_frame_prefix(b"  12:34: x"),
            Some((2, 8, make_symbol_key(12, 34)))
        );
        assert_eq!(parse_frame_prefix(b"x12:3:"), None);
        assert_eq!(parse_frame_prefix(b"12:3"), None);
        assert_eq!(parse_frame_prefix(b"12::"), None);
        assert_eq!(parse_frame_prefix(b""), None);
    }

    #[test]
    fn stack_trace_rewrites_symbol_and_stock_frames() {
        let mut symbols = SymbolMap::new();
        symbols.insert(
            make_symbol_key(1234, 5),
            SymbolRecord {
                source: b"scripts/a.gsc".to_vec(),
                source_line: 42,
                function_name: b"fn_a".to_vec(),
            },
        );
        let mut stock = StockSymbolMap::new();
        stock.insert(
            1234,
            StockSymbolRecord {
                source: b"stock/b.gsc".to_vec(),
                function_name: b"fn_b".to_vec(),
            },
        );
        stock.insert(
            9999,
            StockSymbolRecord {
                source: b"stock/c.gsc".to_vec(),
                function_name: Vec::new(),
            },
        );
        stock.insert(
            8888,
            StockSymbolRecord {
                source: b"stock/d.gsc".to_vec(),
                function_name: b"fn_c".to_vec(),
            },
        );

        let trace = b"stack traceback:\n\
            \t1234:5: in function '(*stripped)'\n\
            \t9999:7: in function '(*stripped)'\n\
            \t8888:1: in function '(*stripped)'\n";
        let (rewritten, resolved) = rewrite_stack_trace(trace, &symbols, &stock);
        assert_eq!(resolved, 3);
        assert_eq!(
            rewritten,
            b"stack traceback:\n\
              \tscripts/a.gsc:42: in function 'fn_a'\n\
              \tstock/c.gsc:pc7: in function '(*stripped)'\n\
              \tstock/d.gsc:pc1: in function 'fn_c'\n"
                .to_vec()
        );
    }

    #[test]
    fn stack_trace_without_known_frames_is_unchanged() {
        let trace = b"a\n\tplain: frame\nlast";
        let (rewritten, resolved) =
            rewrite_stack_trace(trace, &SymbolMap::new(), &StockSymbolMap::new());
        assert_eq!(resolved, 0);
        assert_eq!(rewritten, trace.to_vec());
    }

    #[test]
    fn live_prototype_reads_top_frame() {
        let memory = live_fixture();
        assert_eq!(
            live_prototype(&memory, STATE, DEBUG),
            Some((HASH, INSTRUCTIONS))
        );
    }

    #[test]
    fn live_prototype_reads_frame_below_top() {
        let mut memory = live_fixture();
        memory.write_i32(DEBUG + DEBUG_LEVEL_OFFSET, 0);
        assert_eq!(
            live_prototype(&memory, STATE, DEBUG),
            Some((HASH, INSTRUCTIONS))
        );
    }

    #[test]
    fn live_prototype_rejects_inconsistent_state() {
        let mut level_too_high = live_fixture();
        level_too_high.write_i32(DEBUG + DEBUG_LEVEL_OFFSET, 3);
        assert_eq!(live_prototype(&level_too_high, STATE, DEBUG), None);

        let mut tail_call = live_fixture();
        tail_call.write_i32(DEBUG + DEBUG_TAIL_CALL_OFFSET, 1);
        assert_eq!(live_prototype(&tail_call, STATE, DEBUG), None);

        let mut bad_type = live_fixture();
        bad_type.write_usize(FUNCTION - HKS_OBJECT_SIZE, 8);
        assert_eq!(live_prototype(&bad_type, STATE, DEBUG), None);

        let mut zero_hash = live_fixture();
        zero_hash.write_u32(METHOD + METHOD_HASH_OFFSET, 0);
        assert_eq!(live_prototype(&zero_hash, STATE, DEBUG), None);

        let mut misaligned = live_fixture();
        misaligned.write_usize(STATE + STATE_CURRENT_OFFSET, RECORDS + 25);
        assert_eq!(live_prototype(&misaligned, STATE, DEBUG), None);

        assert_eq!(live_prototype(&live_fixture(), 0, DEBUG), None);
    }

    #[test]
    fn live_name_needs_a_matching_bytecode_header() {
        let text = b"43981,scripts/a.gsc,16,main\n";
        let databases = parse_stock_database(&text[..]);

        let mut memory = FakeMemory::default();
        assert!(resolve_live_function_name(&memory, &databases, HASH, INSTRUCTIONS).is_none());

        memory.write_u32(INSTRUCTIONS - 16, LUA_BYTECODE_HEADER);
        let name = resolve_live_function_name(&memory, &databases, HASH, INSTRUCTIONS)
            .expect("header matches");
        assert_eq!(name.to_str(), Ok("main"));
    }

    #[test]
    fn live_name_is_unknown_when_two_closures_match() {
        let text = b"43981,a.gsc,16,main\n43981,a.gsc,16,other\n";
        let databases = parse_stock_database(&text[..]);
        let mut memory = FakeMemory::default();
        memory.write_u32(INSTRUCTIONS - 16, LUA_BYTECODE_HEADER);
        assert!(resolve_live_function_name(&memory, &databases, HASH, INSTRUCTIONS).is_none());
    }

    #[test]
    fn stripped_name_compares_the_full_c_string() {
        let mut memory = FakeMemory::default();
        memory.write(0x100, b"(*stripped)\0");
        memory.write(0x200, b"(*stripped)x");
        assert!(is_stripped_name(&memory, 0x100));
        assert!(!is_stripped_name(&memory, 0x200));
        assert!(!is_stripped_name(&memory, 0x300));
    }
}
