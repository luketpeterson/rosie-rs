#![crate_name = "rosie"]

#![doc(html_logo_url = "https://rosie-lang.org/images/rosie-circle-blog.png")]
//Q-06.04, Can Jamie host a version of this logo that doesn't have a border?  i.e. just the circle occupying the whole frame, with an alpha-channel so the corners are transparent

#![doc = include_str!("../README.md")]

use core::mem::swap;
use core::fmt;
use core::fmt::Display;
use std::str;
use std::convert::{TryFrom, TryInto};
use std::path::{Path, PathBuf};
use std::fs;
use std::sync::Mutex;
use std::cell::UnsafeCell;

use linked_hash_map::LinkedHashMap;

use once_cell::sync::Lazy; // TODO: As soon as std::sync::SyncLazy is pushed to stable, we will migrate there and eliminate this dependency

extern crate rosie_sys;
use rosie_sys::{
    RosieString,
    rosie_new_string,
    rosie_home_default,
    rosie_home_init,
    rosie_free_rplx,
};

//Private Internal code for managing most calls into librosie
mod sys_wrapper;
use sys_wrapper::{*};

//Public re-exports
mod sys_shadow; //Shadow implementations of things from rosie_sys::
pub use sys_shadow::RosieError; //pub use rosie_sys::RosieError;
/// An Encoder module used to format the results, when using [Pattern::raw_match]
pub use rosie_sys::MatchEncoder;
/// A structure containing the match results from a [Pattern::raw_match] call.
/// 
/// **NOTE**: A RawMatchResult points to memory inside the engine that is associated with the pattern, therefore you may
/// not perform any additional matching with that pattern until the RawMatchResult has been released.  This is enforced with
/// borrowing semantics [Pattern::raw_match].
pub use rosie_sys::RawMatchResult;
/// A format for debugging output, to be used with [Pattern::trace]
pub use rosie_sys::TraceFormat;

/// Functionality to access [RosieEngine]s directly
/// 
/// The majority of use cases don't require direct access to a RosieEngine.  However, this module can be used to:
/// - Create multiple simultaneous engines
/// - Change the environment (Standard Pattern Library or config)
/// - Explicitly load rpl packages 
/// - Constrain memory usage
/// 
/// ## Example Usage
/// ```
/// use rosie::*;
/// let mut engine = engine::RosieEngine::new(None).unwrap();
/// engine.import_pkg("date", None, None);
/// 
/// let date_pat = engine.compile("date.us_long", None).unwrap();
/// assert!(date_pat.match_str::<bool>("Saturday, Nov 5, 1955").unwrap());
/// ```
/// 
pub mod engine {
    pub use crate::sys_wrapper::RosieEngine;
}

//The number of compiled patterns in the pattern cache
const PATTERN_CACHE_SIZE: usize = 8;

//Global to track the state of librosie
static LIBROSIE_INITIALIZED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

//Global per-thread singleton engine and pattern cache
struct ThreadLocals {
    engine : RosieEngine,
    pattern_cache : LinkedHashMap<String, Pattern>
}
thread_local!{
    //TODO: Waiting for the stabilization of `#[thread_local]` attribute so we can get rid of this UnsafeCell
    // Don't want to pay the price of a RefCell for no reason
    // https://github.com/rust-lang/rust/issues/29594
    static THREAD_LOCALS : UnsafeCell<ThreadLocals> = UnsafeCell::new(ThreadLocals::new())
}

impl ThreadLocals {
    fn new() -> Self {
        Self {
            engine : {
                let mut messages = RosieMessage::empty();
                if let Ok(engine) = RosieEngine::new(Some(&mut messages)) {
                    engine
                } else {
                    panic!("ERROR Creating RosieEngine: {}", messages.as_str())
                }
            },
            pattern_cache : LinkedHashMap::with_capacity(PATTERN_CACHE_SIZE)
        }
    }
}

/// A buffer to obtain text from Rosie.
/// 
/// The contents of the buffer depend on the situation under which it is returned.
/// Sometimes the returned text is formatted as JSON and other times it is a human-readable message.
/// 
/// # Example: Getting a message from the expression compiler
/// ```
/// # use rosie::*;
/// let mut engine = engine::RosieEngine::new(None).unwrap();
/// let mut message = RosieMessage::empty();
/// engine.compile("invalid pattern", Some(&mut message));
/// println!("{}", message);
/// ```
#[derive(Debug)]
pub struct RosieMessage(RosieString<'static>);

//For some strings, we are responsible for freeing any string buffers, even if librosie allocated them
impl Drop for RosieMessage {
    fn drop(&mut self) {
        self.0.manual_drop();
    }
}

impl RosieMessage {
    /// Creates an empty RosieMessage.  Used to allocate a location into which another function may write output.
    pub fn empty() -> Self {
        Self(RosieString::empty())
    }
    /// Creates a new RosieMessage by copying the contents of the argument &[str](std::str) into the newly created RosieMessage.
    pub fn from_str(s: &str) -> Self {
        let rosie_string = unsafe { rosie_new_string(s.as_ptr(), s.len()) };
        Self(rosie_string)
    }
    /// Returns `true` if the RosieMessage contains text.  Returns `false` if it is empty.
    pub fn is_valid(&self) -> bool {
        self.0.is_valid()
    }
    /// Borrows the RosieMessage contents as a slice of bytes.  If the RosieMessage is empty the resulting slice will have a length of zero.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    /// Borrows the RosieMessage contents as a &[str](std::str).  If the RosieMessage is empty the result will have a length of zero.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    /// Same as [as_str](RosieMessage::as_str) but won't panic
    pub fn try_as_str(&self) -> Option<&str> {
        self.0.try_as_str()
    }
    /// Returns the length, in bytes, of the contents of the RosieMessage.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Display for RosieMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The interface to top-level rosie functionality
pub struct Rosie ();

impl Rosie {
    /// Matches the specified `expression` in the specified `input` bytes.
    /// 
    /// Returns the requested type if a match was found, otherwise returns an appropriate error code.
    /// 
    /// Compiled patterns are managed automatically using a least-recently-used cache and are recompiled as needed.
    /// 
    /// NOTE: This method may return several different return types, including [bool], and [MatchResult].
    /// If you need the fastest possible performance calling this method to return a [bool] will use the
    /// [Bool](MatchEncoder::Bool) encoder and bypass a lot of overhead formatting the results.
    pub fn match_bytes<'input, T>(expression : &str, input : &'input [u8]) -> T 
    where T : MatchOutput<'input> {
        THREAD_LOCALS.with(|locals_cell| {

            //TODO: Get rid of UnsafeCell.  See note near declaration of THREAD_LOCALS.
            let locals : &mut ThreadLocals = unsafe{ &mut *locals_cell.get() };

            //See if we have the expression in our pattern cache
            let mut pat = if let Some(existing_pat) = locals.pattern_cache.remove(expression) {
                existing_pat
            } else {
                //If we don't have the expression, make sure there is space for it in the cache
                if locals.pattern_cache.len() > PATTERN_CACHE_SIZE-1 {
                    //Toss out the least-recently-added item
                    let _ = locals.pattern_cache.pop_front();
                }

                //And compile the expression
                locals.engine.import_expression_deps(expression, None).unwrap();
                locals.engine.compile(expression, None).unwrap()
            };

            //Call the return-type-specific match call
            let result = T::match_bytes(&mut pat, input).unwrap();

            //Put the pattern back on the top of the LRU stack
            locals.pattern_cache.insert(expression.to_string(), pat);

            result
        })
    }
    /// Matches the specified `expression` in the specified `input` str.
    /// 
    /// Returns the requested type if a match was found, otherwise returns an appropriate error code.
    /// 
    /// Compiled patterns are managed automatically using a least-recently-used cache and are recompiled as needed.
    /// 
    /// NOTE: This method may return several different return types, including [bool], and [MatchResult].
    /// If you need the fastest possible performance calling this method to return a [bool] will use the
    /// [Bool](MatchEncoder::Bool) encoder and bypass a lot of overhead formatting the results.
    pub fn match_str<'input, T>(expression : &str, input : &'input str) -> T 
    where T : MatchOutput<'input> {
        Self::match_bytes(expression, input.as_bytes())
    }
    /// Compiles the specified expression, returning a `Pattern` that can then be used to match that expression.
    /// 
    /// The expression may be either the name of a previously loaded `rpl` pattern, or it may be a raw `rpl` expression.
    /// 
    /// **NOTE**: This method is high-level.  If you want more control, performance, or feedback, see [RosieEngine::compile].
    /// 
    /// - This method automatically evaluates the expression for dependencies and automatically loads any dependencies it
    /// finds, while RosieEngine::compile skips the dependency analysis
    /// - This method's returned `Pattern` will be hosted by the thread's default engine.  RosieEngine::compile allows you
    /// to host the Pattern on another engine
    /// - This method doesn't provide any compile warnings or errors.  To debug a compilation failure, call
    /// RosieEngine::compile
    /// 
    /// # Examples
    /// ```
    /// # use rosie::*;
    /// let date_pat = Rosie::compile("date.us_long").unwrap();
    /// ```
    /// 
    /// ```
    /// # use rosie::*;
    /// let two_digit_year_pat = Rosie::compile("{[012][0-9]}").unwrap();
    /// ```
    /// 
    pub fn compile(expression : &str) -> Result<Pattern, RosieError> {
        THREAD_LOCALS.with(|locals_cell| {
            
            //TODO: Get rid of UnsafeCell.  See note near declaration of THREAD_LOCALS.
            let locals : &ThreadLocals = unsafe{ &*locals_cell.get() };

            locals.engine.import_expression_deps(expression, None)?;
            locals.engine.compile(expression, None)
        })
    }
    /// Sets a custom location for the rosie_home path used for support scripts and the default Standard Pattern Library. 
    /// 
    /// **WARNING** This method must be called before any other rosie calls, or it will not be sucessful
    pub fn set_rosie_home_path<P: AsRef<Path>>(path: P) {
        librosie_init(Some(path))
    }
    /// Returns the thread's default RosieEngine, replacing it with a newly initialized engine
    /// 
    /// NOTE: This will clear the compiled pattern cache used by [Rosie::match_str]
    /// 
    pub fn take_thread_default_engine() -> RosieEngine {
        THREAD_LOCALS.with(|locals_cell| {

            //TODO: Get rid of UnsafeCell.  See note near declaration of THREAD_LOCALS.
            let locals : &mut ThreadLocals = unsafe{ &mut *locals_cell.get() };

            let mut new_locals = ThreadLocals::new();
            swap(&mut new_locals, locals);
            new_locals.engine
        })
    }
    /// Replaces the thread's default RosieEngine with the engine supplied
    /// 
    /// NOTE: This will clear the compiled pattern cache used by [Rosie::match_str]
    /// 
    pub fn replace_thread_default_engine(engine : RosieEngine) {
        THREAD_LOCALS.with(|locals_cell| {

            //TODO: Get rid of UnsafeCell.  See note near declaration of THREAD_LOCALS.
            let locals : &mut ThreadLocals = unsafe{ &mut *locals_cell.get() };

            locals.engine = engine;
            locals.pattern_cache = LinkedHashMap::with_capacity(PATTERN_CACHE_SIZE);
        })
    }
}

/// Implemented for types that can be returned by a match operation
pub trait MatchOutput<'a> : Sized {
    fn match_bytes(pat : &Pattern, input : &'a [u8]) -> Result<Self, RosieError>;
}

impl MatchOutput<'_> for bool {
    fn match_bytes(pat : &Pattern, input : &[u8]) -> Result<Self, RosieError> {
        //NOTE: we're calling directly into the engine because we want to bypass the requirement for a &mut self in Pattern::raw_match.
        // That &mut is just there to ensure we have an exclusive borrow, so subsequent calls don't match the same compiled pattern and
        // collide with the pattern's buffer in the engine.
        let raw_match_result = pat.engine.match_pattern_raw(pat.id, 1, input, &MatchEncoder::Bool).unwrap();
        Ok(raw_match_result.did_match())
    }
}

//IMPLEMENTATION NOTE: I chose to delete the `String` implementation because the common case for MatchResult, i.e. the case where the
// pattern is not a constant-capture pattern means that the matched string is just a slice referencing the input.  But the `String`
// implementation forces a copy in every situation.  So we want to accidentally direct people to the slow-path by making it convenient.
//
//In a perfect world, I would like there to be an implementation for `&'a str`, but the problem with that is constant-capture patterns
// point to data that isn't in the input.  I went pretty far into a change that got rid of the MaybeOwnedBytes inside of MatchResult,
// in order to implement `MatchResult::into_str`, but that meant constant-capture patterns (and therefore all MatchResults) needed to
// borrow the engine buffer associated with the pattern (like a RawMatchResult does).  This is unworkable because of the pattern cache.
//
// impl <'a>MatchOutput<'a> for String {
//     fn match_str(pat : &Pattern, input : &'a str) -> Result<Self, RosieError> {
//         let match_result = pat.engine.match_pattern(pat.id, 1, input)?;
//         Ok(match_result.matched_str().to_string())
//     }
// }

impl <'a>MatchOutput<'a> for MatchResult<'a> {
    fn match_bytes(pat : &Pattern, input : &'a [u8]) -> Result<Self, RosieError> {
        pat.engine.match_pattern(pat.id, 1, input)
    }
}

//Private function to make sure librosie is initialized and initialize it if it isn't
//Internal NOTE: This function is responsible for internal librosie initialization, so it is also called by RosieEngine::new()
fn librosie_init<P: AsRef<Path>>(path: Option<P>) {

    //Get the global status var, or block until we can get it
    let mut init_status = LIBROSIE_INITIALIZED.lock().unwrap();

    //If librosie isn't initialized yet, then initialize it
    if !(*init_status) {

        let mut did_init = false;

        //Decide among the different paths we might use
        let dir_path = if let Some(dir_path) = path {
            Some(PathBuf::from(dir_path.as_ref())) // If we were passed a path, use it.
        } else {
            if let Some(default_path_str) = rosie_home_default() {
                Some(PathBuf::from(str::from_utf8(default_path_str).unwrap())) //We will pass the path compiled into our binary
            } else {
                None //We will let librosie try to find it
            }
        };

        //Make sure the path is a valid directory before calling rosie_home_init(),
        // because rosie_home_init() will buy whatever we're selling, even if it's garbage
        if let Some(dir_path) = dir_path {
            if let Ok(dir_metadata) = fs::metadata(&dir_path) {
                if dir_metadata.is_dir() {
                    let mut message_buf = RosieString::empty();
                    unsafe{ rosie_home_init(&RosieString::from_str(&dir_path.to_str().unwrap()), &mut message_buf) };
                    did_init = true;
                }
            }
        }
        
        *init_status = did_init;
    }
}

/// The compiled form of an RPL expression, used for matching
/// 
/// A Pattern can be created by either [Rosie::compile] or [RosieEngine::compile].
/// 
/// **Performance NOTE**: Compiling a pattern is hundreds of times more expensive than a typical matching operation.
/// Therefore it is usually worthwhile to retain compiled patterns rather than allowing them to be dropped and
/// recompiling them when needed.
/// 
//TODO: Add API to load compiled patterns, without needing to go via RPL, when it is supported by librosie.
//
//INTERNAL NOTE: Pattern doesn't implement Clone because a RawMatchResult holds a pointer to a buffer inside the
// engine, for which there is one-per-pattern.  If a pattern could be cloned, we could end up invalidating the
// memory out from under a RawMatchResult.
pub struct Pattern {
    engine : RosieEngine,
    id : i32
}

impl Drop for Pattern {
    fn drop(&mut self) {
        unsafe { rosie_free_rplx(self.engine.ptr(), self.id) };
    }
}

impl Pattern {
        
    /// Matches the `Pattern` in the specified `input` bytes string.
    /// 
    /// Returns the requested type if a match was found, otherwise returns an appropriate error code.
    /// 
    /// NOTE: This method may return several different return types, including [bool], and [MatchResult].
    /// If you need the fastest possible performance calling this method to return a [bool] will use the
    /// [Bool](MatchEncoder::Bool) encoder and bypass a lot of overhead formatting the results.
    pub fn match_bytes<'input, T>(&self, input : &'input [u8]) -> Result<T, RosieError> 
    where T : MatchOutput<'input> {
        //Call the return-type-specific match call
        T::match_bytes(self, input)
    }
    
    /// Matches the `Pattern` in the specified `input` str.
    /// 
    /// Returns the requested type if a match was found, otherwise returns an appropriate error code.
    /// 
    /// NOTE: This method may return several different return types, including [bool], and [MatchResult].
    /// If you need the fastest possible performance calling this method to return a [bool] will use the
    /// [Bool](MatchEncoder::Bool) encoder and bypass a lot of overhead formatting the results.
    pub fn match_str<'input, T>(&self, input : &'input str) -> Result<T, RosieError> 
    where T : MatchOutput<'input> {
        self.match_bytes(input.as_bytes())
    }

    /// Matches the `Pattern` in the specified `input` string, beginning from the `start` index, using the specified `encoder`.
    /// 
    /// Returns a [RawMatchResult] or an error code if a problem was encountered.  This is a lower-level API than [match_str](Pattern::match_str),
    /// and the primary reason to use it is to get the output from a particular [MatchEncoder].  For example, the [JSON](MatchEncoder::JSON) or [JSONPretty](MatchEncoder::JSONPretty) encoders.
    /// 
    /// **NOTE**: The returned [RawMatchResult] takes a mutable borrow of the `Pattern` because it references internal data
    /// associated with the `Pattern`.  Therefore the `Pattern` cannot be accessed while the RawMatchResult is in use; copying
    /// the data from the RawMatchResult will allow the `Pattern` to be released.
    /// 
    /// **NOTE**: The values for `start` are 1-based.  Meaning passing 1 will begin the match from the beginning of the input, and
    /// passing 0 (zero) is an error.
    /// 
    /// # Example using the JSON encoder with serde_json
    /// ```
    /// extern crate serde_json;
    /// use serde::{*};
    /// use rosie::*;
    /// 
    /// #[derive(Debug, Deserialize)]
    /// struct JSONMatchResult {
    ///     #[serde(rename = "type")]
    ///     pat_name : String, // The pattern that was matched
    ///     #[serde(rename = "s")]
    ///     start : usize, // The offset of the start of the match in the input buffer
    ///     #[serde(rename = "e")]
    ///     end : usize, // The offset of the end of the match in the input buffer
    ///     data : String, // The matched text, copied from the input buffer
    ///     #[serde(default = "Vec::new")]
    ///     subs : Vec<JSONMatchResult> // The sub-matches within the pattern
    /// }
    /// 
    /// let mut date_pat = Rosie::compile("date.any").unwrap();
    /// let raw_result = date_pat.raw_match(1, b"Sat Nov 5, 1955", &MatchEncoder::JSON).unwrap();
    /// let parsed_result : JSONMatchResult = serde_json::from_slice(raw_result.as_bytes()).unwrap();
    /// ```
    /// 
    pub fn raw_match<'pat>(&'pat mut self, start : usize, input : &[u8], encoder : &MatchEncoder) -> Result<RawMatchResult<'pat>, RosieError> {
        self.engine.match_pattern_raw(self.id, start, input, encoder)
    }

    /// Traces a pattern match, providing information useful for debugging the pattern expression.
    /// 
    /// Returns a bool indicating whether the specified pattern matched the input.  The caller must allocate an empty [RosieMessage]
    /// in order to receive the resulting trace information.
    /// 
    /// The caller must also pass a [TraceFormat], to specify the format for the resulting information.
    /// [Condensed](TraceFormat::Condensed) is the most human-readable format, but a other formats may contain more complete
    /// information or be easier to automatically parse.
    /// 
    /// # Example
    /// ```
    /// # use rosie::*;
    /// let date_pat = Rosie::compile("date.any").unwrap();
    /// 
    /// let mut trace = RosieMessage::empty();
    /// let did_match = date_pat.trace(1, "Sat. Nov. 5, 1955", TraceFormat::Condensed, &mut trace).unwrap();
    /// println!("{}", trace.as_str());
    /// ```
    ///
    pub fn trace(&self, start : usize, input : &str, format : TraceFormat, trace : &mut RosieMessage) -> Result<bool, RosieError> {
        self.engine.trace_pattern(self.id, start, input, format, trace)
    }
}

//A variant on maybe_owned::MaybeOwned, except it can either be a Vec<u8> or an &[u8].
#[derive(Debug)]
enum MaybeOwnedBytes<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a [u8]),
}

impl MaybeOwnedBytes<'_> {
    pub fn try_as_str(&self) -> Option<&str> {
        str::from_utf8(self.as_bytes()).ok()
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MaybeOwnedBytes::Owned(the_vec) => &the_vec[..],
            MaybeOwnedBytes::Borrowed(the_slice) => the_slice
        }
    }
}

/// Represents the results of a match operation, performed by [Pattern::match_str] or [Rosie::match_str]
/// 
//**TODO** I feel like a more caller-friendly interface is possible; i.e. the ability to specify sub-patterns with a "path"
#[derive(Debug)]
pub struct MatchResult<'a> {
    pat_name : String,
    start : usize,
    end : usize,
    data : MaybeOwnedBytes<'a>,
    subs : Vec<MatchResult<'a>>
}

impl <'a>MatchResult<'a> {

    //This method is a port from the python code here: https://gitlab.com/rosie-community/clients/python/-/blob/master/rosie/decode.py
    fn from_bytes_buffer<'input>(input : &'input [u8], match_buffer : &mut &[u8], existing_start_pos : Option<usize>) -> MatchResult<'input> {

        //If we received a start position, it is because we are in the middle of a recursive call stack
        let start_position = match existing_start_pos {
            Some(start_position) => start_position,
            None => {
                //Otherwise, Read the first 4 bytes, interpret them as a signed little-endian 32 bit integer,
                //  and then negate them to get the start position
                let (start_pos_chars, remainder) = match_buffer.split_at(4);
                *match_buffer = remainder;
                let signed_start_pos = i32::from_le_bytes(start_pos_chars.try_into().unwrap());
                assert!(signed_start_pos < 0);
                usize::try_from(signed_start_pos * -1).unwrap()
            }
        };
        
        //Read the next 2 bytes, interpret them as a signed little-endian 16 but integer,
        let (type_len_chars, remainder) = match_buffer.split_at(2);
        *match_buffer = remainder;
        let mut type_len = i16::from_le_bytes(type_len_chars.try_into().unwrap()); //The length of the pattern name

        //constant-capture means data is a user-provided string, (i.e. a string from the encoder)
        //Otherwise regular-capture means data is a subset of the input string
        let constant_capture = if type_len < 0 {
            type_len = type_len * -1;
            true
        } else {
            false
        };
        
        //Read type_len characters, intperpreting it as the pattern name
        let (type_name_chars, remainder) = match_buffer.split_at(usize::try_from(type_len).unwrap());
        *match_buffer = remainder;
        let pattern_name = String::from_utf8(type_name_chars.to_vec()).unwrap();

        //Get the data out of the match_buffer, or the input string, depending on whether the pattern is "constant-capture" or not
        let mut data = if constant_capture {
            let (data_len_chars, remainder) = match_buffer.split_at(2);
            *match_buffer = remainder;
            let data_len = i16::from_le_bytes(data_len_chars.try_into().unwrap()); //The length of the data name
            assert!(data_len >= 0);

            let (data_chars, remainder) = match_buffer.split_at(usize::try_from(data_len).unwrap());
            *match_buffer = remainder;
            MaybeOwnedBytes::Owned(data_chars.to_vec())
        } else {
            let (_, match_data) = input.split_at(start_position-1);
            MaybeOwnedBytes::Borrowed(match_data)
        };

        //The empty array for our sub-patterns.
        let mut subs = Vec::new();
        
        //Read the next 4 bytes, and interpret them as a little-endian signed int.  It it's negative, then
        //that means we negate it to get the start of the next sub-match, and call ourselves recursively to.
        //continue parsing the sub-match.  If the number is positive, then we have come to the end of this
        //sub-pattern array, so the number is the end position of this pattern.
        let end_position;
        loop {
            let (next_pos_chars, remainder) = match_buffer.split_at(4);
            *match_buffer = remainder;
            let signed_next_pos = i32::from_le_bytes(next_pos_chars.try_into().unwrap());
            
            if signed_next_pos < 0 {
                let next_position = usize::try_from(signed_next_pos * -1).unwrap();
                let sub_match = MatchResult::from_bytes_buffer(input, match_buffer, Some(next_position));
                subs.push(sub_match);
            } else {
                end_position = usize::try_from(signed_next_pos).unwrap();
                break;
            }
        }

        //If we have a borrowed data pointer, cut its length at the appropriate place
        if let MaybeOwnedBytes::Borrowed(match_data) = data {
            let (new_data_ref, _) = match_data.split_at(end_position - start_position);
            data = MaybeOwnedBytes::Borrowed(new_data_ref);
        }
        
        MatchResult{
            pat_name : pattern_name,
            start : start_position,
            end : end_position,
            data : data,
            subs : subs
        }
    }
    fn from_byte_match_result<'input>(input : &'input [u8], src_result : RawMatchResult) -> MatchResult<'input> {
        let mut data_buf_ref = src_result.as_bytes();
        MatchResult::from_bytes_buffer(input, &mut data_buf_ref, None)
    }
    fn new_no_match() -> MatchResult<'static> {
        MatchResult{
            pat_name : "".to_string(),
            start : 0,
            end : 0,
            data : MaybeOwnedBytes::Borrowed(&[]),
            subs : vec![]
        }
    }
    /// Returns `true` if the pattern was matched in the input, otherwise returns `false`.
    pub fn did_match(&self) -> bool {
        if self.start == 0 && self.end == 0 {
            false
        } else {
            true
        }
    }
    /// Returns the name of the pattern that matched
    pub fn pat_name_str(&self) -> &str {
        self.pat_name.as_str()
    }
    /// Returns the subset of the input that was matched by the pattern as an &str
    /// 
    /// NOTE: This may panic if the matched data includes part but not all of a unicode character.
    /// Use [try_matched_str](Self::try_matched_str) for a non-panicking alternative
    pub fn matched_str(&self) -> &str {
        self.try_matched_str().unwrap()
    }
    /// Returns the subset of the input that was matched by the pattern as an &str
    pub fn try_matched_str(&self) -> Option<&str> {
        self.data.try_as_str()
    }
    /// Returns the subset of the input that was matched by the pattern as an &[u8]
    pub fn matched_bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }
    /// Returns the character offset of the beginning of the match, within the input
    /// 
    /// NOTE: Offsets are 1-based
    pub fn start(&self) -> usize {
        self.start
    }
    /// Returns the character offset, within the input, of the end of the match
    /// 
    /// NOTE: Offsets are 1-based
    pub fn end(&self) -> usize {
        self.end
    }
    /// Returns the number of matched sub-patterns that comprise the matched pattern
    pub fn sub_pat_count(&self) -> usize {
        self.subs.len()
    }
    /// Returns an [Iterator] over all of the sub-patterns within this matched pattern
    pub fn sub_pat_iter(&self) -> impl Iterator<Item=&MatchResult> {
        self.subs.iter()
    }
}

#[cfg(test)]
mod tests {
    use crate::{*};
    use std::thread;
    use rand::prelude::*;
    use rand_pcg::Pcg64;

    #[test]
    /// Tests the RosieString and RosieMessage functionality, without a RosieEngine
    fn rosie_string() {

        //A basic RosieString, pointing to a static string
        let hello_str = "hello";
        let rosie_string = RosieString::from_str(hello_str);
        assert_eq!(rosie_string.len(), hello_str.len());
        assert_eq!(rosie_string.as_str(), hello_str);

        //A RosieString pointing to a heap-allocated string
        let hello_string = String::from("hi there");
        let rosie_string = RosieString::from_str(hello_string.as_str());
        assert_eq!(rosie_string.len(), hello_string.len());
        assert_eq!(rosie_string.as_str(), hello_string);

        //Ensure we can't deallocate our rust String without deallocating our RosieString first
        drop(hello_string);
        //TODO: Implement a TryBuild harness in order to ensure the line below will not compile 
        //assert!(rosie_string.is_valid());

        //Make a RosieMessage, pointing to a heap-allocated string
        let hello_string = String::from("howdy");
        let rosie_message = RosieMessage::from_str(hello_string.as_str());
        assert_eq!(rosie_message.len(), hello_string.len());
        assert_eq!(rosie_message.as_str(), hello_string);

        //Now test that we can safely deallocate the heap-allocated String that we used to create a RosieMessage
        drop(hello_string);
        assert!(rosie_message.is_valid());
    }

    #[test]
    /// Some tests for working with the default thread singleton engine
    fn default_engine() {

        //Try with the one liner, returning a bool
        assert!(Rosie::match_str::<bool>("{ [H][^]* }", "Hello, Rosie!"));

        //Try with explicit compilation using the default engine
        let pat = Rosie::compile("{ [H][^]* }").unwrap();
        let result : MatchResult = pat.match_str("Hello, Rosie!").unwrap();
        assert_eq!(result.matched_str(), "Hello, Rosie!");

        //Take the default engine and then drop it, but make sure extant patterns aren't affected
        let engine = Rosie::take_thread_default_engine();
        drop(engine);
        assert!(pat.match_str::<bool>("Hello, Rosie!").unwrap());

        //Create a new explicit engine, and make it the default, and ensure everything is ok
        let engine = RosieEngine::new(None).unwrap();
        Rosie::replace_thread_default_engine(engine);
        let new_pat = Rosie::compile("{ [H][^]* }").unwrap();
        assert!(pat.match_str::<bool>("Hello, Rosie!").unwrap());
        assert!(new_pat.match_str::<bool>("Hello, Rosie!").unwrap());
    }

    #[test]
    /// Tests the interfaces to explicitly manage RosieEngines
    fn explicit_engine() {

        //Create the engine and check that it was sucessful
        let mut engine = RosieEngine::new(None).unwrap();

        //Make sure we can get the engine config
        let _ = engine.config_as_json().unwrap();

        //Check that we can get the library path, and then append a new path to it
        let mut lib_paths = engine.lib_paths().unwrap();
        //println!("lib_paths[0] = {}", lib_paths[0].display());

        //Now append a new path to it
        let new_rpl_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_rpl");
        lib_paths.push(new_rpl_dir);
        engine.set_lib_paths(&lib_paths).unwrap();

        //Make sure we can read it back and see the path we added, in addition to the original
        let lib_paths = engine.lib_paths().unwrap();
        assert_eq!(lib_paths.len(), 2);
        assert!(lib_paths.contains(&Path::new(env!("CARGO_MANIFEST_DIR")).join("test_rpl")));

        //Validate we can find packages in the new directory
        engine.import_expression_deps("rust_test_1.c_vegetables", None).unwrap();

        //Check the alloc limit, set it to unlimited, check the usage
        let _ = engine.mem_alloc_limit().unwrap();
        assert!(engine.set_mem_alloc_limit(0).is_ok());
        let _ = engine.mem_usage().unwrap();

        //Compile a valid rpl pattern, and confirm there is no error
        let pat = engine.compile("{[012][0-9]}", None).unwrap();

        //Make sure we can sucessfully free the pattern
        drop(pat);
        
        //Try to compile an invalid pattern (syntax error), and check the error and error message
        let mut message = RosieMessage::empty();
        let compile_result = engine.compile("year = bogus", Some(&mut message));
        assert!(compile_result.is_err());
        assert!(message.len() > 0);
        //println!("Compile Error: {}", message.as_str());

        //Try and import the dependencies for an invalid pattern, and check the error message
        let mut message = RosieMessage::empty();
        let import_result = engine.import_expression_deps("invalid.any", Some(&mut message));
        assert!(import_result.is_err());
        assert!(message.len() > 0);
        //println!("Import Error: {}", message.as_str());

        //Load the dependencies for a valid pattern
        engine.import_expression_deps("time.any", None).unwrap();

        //Recompile a pattern expression and match it against a matching input using match_pattern_raw
        let mut pat = engine.compile("{[012][0-9]}", None).unwrap();
        let raw_match_result = pat.raw_match(1, b"21", &MatchEncoder::Bool).unwrap();
        //Validate that we can't access the pattern while our raw_match_result is in use.
        //TODO: Implement a TryBuild harness in order to ensure the two lines below will not compile together, although each will compile separately.
        // assert!(!pat.match_str::<bool>("35").unwrap());
        assert_eq!(raw_match_result.did_match(), true);
        assert!(raw_match_result.time_elapsed_matching() <= raw_match_result.time_elapsed_total()); //A little lame as tests go, but validates they are called at least.

        //Now try the match with the high-level match_str call
        let match_result : MatchResult = pat.match_str("21").unwrap();
        assert_eq!(match_result.pat_name_str(), "*");
        assert_eq!(match_result.matched_str(), "21");
        assert_eq!(match_result.start(), 1);
        assert_eq!(match_result.end(), 3);
        assert_eq!(match_result.sub_pat_count(), 0);

        //Try it against non-matching input, and make sure we get no match
        let match_result : MatchResult = pat.match_str("99").unwrap();
        assert_eq!(match_result.did_match(), false);

        //Test the trace method, and make sure we get a reasonable result
        let mut trace = RosieMessage::empty();
        assert!(pat.trace(1, "21", TraceFormat::Condensed, &mut trace).is_ok());
        assert!(trace.as_str().len() > 0);
        //println!("{}", trace.as_str());

        //Test loading a package from a string
        let pkg_name = engine.load_pkg_from_str("package two_digit_year\n\nyear = {[012][0-9]}", None).unwrap();
        assert_eq!(pkg_name.as_str(), "two_digit_year");

        //Test loading a package from a file
        let rpl_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_rpl").join("rust_test_2.rpl");
        let pkg_name = engine.load_pkg_from_file(rpl_file.to_str().unwrap(), None).unwrap();
        assert_eq!(pkg_name.as_str(), "rust_test_2");

        //Test importing a package
        let pkg_name = engine.import_pkg("net", None, None).unwrap();
        assert_eq!(pkg_name.as_str(), "net");

        //Test matching a pattern with some recursive sub-patterns
        engine.import_pkg("date", None, None).unwrap();
        let mut date_pat = engine.compile("date.us_long", None).unwrap();
        let match_result : MatchResult = date_pat.match_str("Saturday, Nov 5, 1955").unwrap();
        assert_eq!(match_result.pat_name_str(), "date.us_long");
        assert_eq!(match_result.matched_str(), "Saturday, Nov 5, 1955");
        assert_eq!(match_result.start(), 1);
        assert_eq!(match_result.end(), 22);
        assert_eq!(match_result.sub_pat_count(), 4);
        let sub_match_pat_names : Vec<&str> = match_result.sub_pat_iter().map(|result| result.pat_name_str()).collect();
        assert!(sub_match_pat_names.contains(&"date.day_name"));
        assert!(sub_match_pat_names.contains(&"date.month_name"));
        assert!(sub_match_pat_names.contains(&"date.day"));
        assert!(sub_match_pat_names.contains(&"date.year"));
        let sub_result = match_result.sub_pat_iter().find(|sub_result| sub_result.pat_name_str() == "date.month_name").unwrap();
        assert_eq!(sub_result.matched_str(), "Nov");
        assert_eq!(sub_result.start(), 11);
        assert_eq!(sub_result.end(), 14);

        //Verify that the RawMatchResults from two different compiled patterns don't interfere with each other
        //Also test the JSONPretty encoder while we're at it
        engine.import_expression_deps("time.any", None).unwrap();
        let mut time_pat = engine.compile("time.any", None).unwrap();
        let date_raw_match_result = date_pat.raw_match(1, b"Saturday, Nov 5, 1955", &MatchEncoder::JSONPretty).unwrap();
        let time_raw_match_result = time_pat.raw_match(1, b"2:21 am", &MatchEncoder::JSONPretty).unwrap();
        assert!(date_raw_match_result.as_str() != time_raw_match_result.as_str());
        //NOTE: I know these checks might break with perfectly legal changes to JSON formatting, but at least they
        // will flag it, so a human can take a look and ensure something more fundamental didn't break.
        assert_eq!(date_raw_match_result.as_str().len(), 660);
        assert_eq!(time_raw_match_result.as_str().len(), 453);
    }

    #[test]
    /// Tests a whole bunch of threads all doing compiling and matching at the same time
    fn thread_stress() {

        const NUM_THREADS : usize = 50;
        const NUM_ITERATIONS : usize = 50; //Each iteration includes one compile
        const NUM_MATCHES : usize = 500; //Number of matches to perform each iteration

        let mut thread_handles = vec![];

        for thread_idx in 0..NUM_THREADS {
            let handle = thread::spawn(move || {

                let mut rng = Pcg64::seed_from_u64(thread_idx.try_into().unwrap()); //non-cryptographic random used for repeatability

                for _ in 0..NUM_ITERATIONS {

                    let pat_idx : u8 = rng.gen_range(0..3);
                    let pat_expr = match pat_idx {
                        0 => "{ [H][^]* }",
                        1 => "date.any",
                        2 => "time.any",
                        _ => panic!()
                    };

                    let pat = Rosie::compile(pat_expr).unwrap();

                    for _ in 0..NUM_MATCHES {

                        let str_idx : u8 = rng.gen_range(0..3);
                        let str_val = match str_idx {
                            0 => "Hello, Rosie!",
                            1 => "Saturday, Nov 5, 1955",
                            2 => "2:21 am",
                            _ => panic!()
                        };
    
                        let result : MatchResult = pat.match_str(str_val).unwrap();
    
                        match (pat_idx, str_idx) {
                            (0, 0) => assert_eq!(result.matched_str(), "Hello, Rosie!"),
                            (1, 1) => assert_eq!(result.matched_str(), "Saturday, Nov 5, 1955"),
                            (2, 2) => assert_eq!(result.matched_str(), "2:21 am"),
                            _ => assert!(!result.did_match()),
                        }
                    }
                }
            });

            thread_handles.push(handle);
        }

        //Make sure every thread has a chance to finish
        for handle in thread_handles {
            handle.join().unwrap();
        }
    }

}
