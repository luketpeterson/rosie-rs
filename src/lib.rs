#![crate_name = "rosie_rs"]

//! # rosie-rs Overview
//! This crate implements a high-level interface to the [**Rosie**](https://rosie-lang.org/about/) matching engine for the [**Rosie Pattern Language**](https://gitlab.com/rosie-pattern-language/rosie/-/blob/master/README.md)\(`rpl`\).
//! 
//! Complete reference documentation for `rpl` is [here](https://gitlab.com/rosie-pattern-language/rosie/-/blob/master/doc/rpl.md),
//! and additional examples can be found [here](https://gitlab.com/rosie-pattern-language/rosie/-/blob/master/extra/examples/README.md).
//! 
//! ## Installation
//! This crate dynamically links against the `librosie` library already installed on the target system.  Therefore `librosie` must be installed prior to using this crate.
//! 
//! Complete installation info is [here](https://gitlab.com/rosie-pattern-language/rosie#local-installation).
//! However, Rosie may be available through your package-manager of choice.  For example, you may run one of the following:
//! 
// * `apt-get install rosie`  Q-01.05 QUESTION apt packaged needed!!
//! * `dnf install rosie`
//! * `brew install rosie`
//! 
//! Or if you would prefer to install Rosie from source, [Here](https://rosie-lang.org/blog/2020/05/03/new-build.html) are instructions.
//! 
//! **NOTE**: This crate has been tested aganst `librosie` version **1.2.2**, although it may be compatible with other versions.
//! 
//! **NOTE**: In the future, I would like to create a rosie-sys crate, that could build `librosie` from source, and also provide an option for static linking.
// (Q-01.02 QUESTION & Q-01.01 QUESTION)
//! 
//! ## In Cargo.toml
//! Add the following line to your Cargo.toml `[dependencies]` section:
//! 
//! `rosie-rs = "0.1.0"`
//! 
//! ## Usage
//! 
//! There are 3 levels of depth at which you may access Rosie.
//! 
//! ### High-Level: With `Rosie::match_str()`
//! 
//! Just one-line to check for a match
//! ```
//! use rosie_rs::*;
//! 
//! if Rosie::match_str("{ [H][^]* }", "Hello, Rosie!") {
//!     println!("It Matches!");
//! }
//! ```
//! Or to get the matched substring
//! ```
//! # use rosie_rs::*;
//! let the_str : &str = Rosie::match_str("date.any", "Of course! Nov 5, 1955! That was the day");
//! println!("Matched Substr = {}", the_str);
//! assert_eq!(the_str, "Nov 5, 1955");
//! ```
//! 
//! Compiled patterns are managed automatically using a least-recently-used cache and they are recompiled as needed.
//! 
//! ### Mid-Level: With compiled Patterns
//! 
//! Explicit compilation reduces overhead because you can manage compiled patterns yourself, dropping the patterns you don't need
//! and avoiding unnecessary recompilation.
//! ```
//! use rosie_rs::*;
//! 
//! let date_pat = Pattern::compile("date.us_long").unwrap();
//! let match_result = date_pat.match_str("Saturday, Nov 5, 1955").unwrap();
//! println!("did_match = {}", match_result.did_match());
//! println!("matched_str = {}", match_result.matched_str());
//! ```
//! 
//! ### Low-Level: With a RosieEngine
//! 
//! See [engine] for details.
//! 

//GOAT, I think next I should create a "Rosie" object, and make "compile" be a member of that, along with set_rosie_home, and the call to execute stuff with the default engine.

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
/// An Encoder Module used to format the results, when using [Pattern::match_raw]
pub use rosie_sys::MatchEncoder;
/// A structure containing the match results from a [Pattern::match_raw] call.
/// 
/// **NOTE**: A RawMatchResult points to memory inside the engine that is associated with the pattern, therefore you may
/// not perform any additional matching with that pattern until the RawMatchResult has been released.  This is enforced with
/// borrowing semantics [Pattern::match_raw].
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
/// use rosie_rs::*;
/// let mut engine = engine::RosieEngine::new(None).unwrap();
/// engine.import_pkg("date", None, None);
/// 
/// let date_pat = engine.compile("date.us_long", None).unwrap();
/// let match_result = date_pat.match_str("Saturday, Nov 5, 1955").unwrap();
/// ```
/// 
pub mod engine {
    pub use crate::sys_wrapper::RosieEngine;
}

//The number of compiled patterns in the pattern cache
const PATTERN_CACHE_SIZE: usize = 8;

//Global to track the state of librosie
static LIBROSIE_INITIALIZED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

//Global per-thread singleton engines, and pattern cache
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
/// # Example: Getting Messages from the Expression Compiler
/// ```
/// # use rosie_rs::*;
/// let mut engine = engine::RosieEngine::new(None).unwrap();
/// let mut message = RosieMessage::empty();
/// engine.compile("invalid pattern", Some(&mut message));
/// println!("{}", message.as_str());
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
    /// Returns the length, in bytes, of the contents of the RosieMessage.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// The interface to top-level rosie functionality
pub struct Rosie ();

impl Rosie {
    /// Document this GOAT
    pub fn match_str<'input, T>(expression : &str, input : &'input str) -> T 
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
                    let _ = locals.pattern_cache.pop_front(); //GOAT, this is what I really want
                }

                //And compile the expression
                locals.engine.load_expression_deps(expression, None).unwrap();
                locals.engine.compile(expression, None).unwrap()
            };

            //Call the return-type-specific match call
            let result = T::match_str(&mut pat, input).unwrap();

            //Put the pattern back on the top of the LRU stack
            locals.pattern_cache.insert(expression.to_string(), pat);

            result
        })
    }
}

/// Implemented for types that can be returned by a match operation
pub trait MatchOutput<'a> : Sized {
    fn match_str(pat : &mut Pattern, input : &'a str) -> Result<Self, RosieError>;
}

impl MatchOutput<'_> for bool {
    fn match_str(pat : &mut Pattern, input : &str) -> Result<Self, RosieError> {
        let raw_match_result = pat.match_raw(1, input, &MatchEncoder::Bool).unwrap();
        Ok(raw_match_result.did_match())
    }
}

impl <'a>MatchOutput<'a> for &'a str {
    fn match_str(pat : &mut Pattern, input : &'a str) -> Result<Self, RosieError> {
        let match_result = pat.engine.match_pattern(pat.id, 1, input)?;
        //Ok(match_result.into_matched_str()) //TO Make this work, I think I need to make match_str (not just match_raw) retain a borrow to the engine as well as the input, and then get rid of the MaybeOwned inside of MatchResult
        Ok("goatgoat")
    }
}

//GOAT, implement MatchOutput for MatchResult

//GOAT, convert Pattern::match_str to use the generic return types as well

/// This function can be used to set a custom location for the rosie_home path.
/// 
/// **WARNING** This function must be called before any other rosie calls, or it will not be sucessful
pub fn set_rosie_home_path<P: AsRef<Path>>(path: P) {
    librosie_init(Some(path))
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
                Some(PathBuf::from(default_path_str)) //We will pass the path compiled into our binary
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

//GOAT, include Rosie badge in RustDoc

impl Pattern {
    /// Compiles the specified expression, returning a `Pattern` that can then be used to match that expression.
    /// 
    /// The expression may be either the name of a previously loaded `rpl` pattern, or it may be a raw `rpl` expression.
    /// 
    /// **NOTE**: This function is high-level.  If you want more control, performance, or feedback, see [RosieEngine::compile].
    /// 
    /// - This function automatically evaluates the expression for dependencies and automatically loads any dependencies it
    /// finds, while RosieEngine::compile skips the dependency analysis
    /// - This function's returned `Pattern` will be hosted by the thread's default engine.  RosieEngine::compile allows you
    /// to host the Pattern on another engine
    /// - This function doesn't provide any compile warnings or errors.  To debug a compilation failure, call
    /// RosieEngine::compile
    /// 
    /// # Examples
    /// ```
    /// # use rosie_rs::*;
    /// let date_pat = Pattern::compile("date.us_long").unwrap();
    /// ```
    /// 
    /// ```
    /// # use rosie_rs::*;
    /// let two_digit_year_pat = Pattern::compile("{[012][0-9]}").unwrap();
    /// ```
    /// 
    pub fn compile(expression : &str) -> Result<Self, RosieError> {
        THREAD_LOCALS.with(|locals_cell| {
            
            //TODO: Get rid of UnsafeCell.  See note near declaration of THREAD_LOCALS.
            let locals : &ThreadLocals = unsafe{ &*locals_cell.get() };

            //GOAT, Clean up this, either by calling this from Rosie::match_str
            locals.engine.load_expression_deps(expression, None)?;
            locals.engine.compile(expression, None)
        })
    }

//GOAT, look at a "set / take" default engine model.
//      See if I can check if a thread-local is initialized, so I don't need to wrap it in an Option.
// IMPORTANT.  Taking the default engine must invalidate the pattern cache
    
    /// Matches the `Pattern` in the specified `input` string.
    /// 
    /// Returns a [MatchResult] if a match was found, otherwise returns an appropriate error code.
    /// 
    /// NOTE: This function may return several different return types, including [bool], [&str], and [MatchResult].
    /// If you need the fastest possible performance calling this method to return a [bool] will use the
    /// [Bool](MatchEncoder::Bool) encoder and bypass a lot of overhead formatting the results.
    pub fn match_str<'input>(&self, input : &'input str) -> Result<MatchResult<'input>, RosieError> {
        self.engine.match_pattern(self.id, 1, input)
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
    /// use rosie_rs::*;
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
    /// let mut date_pat = Pattern::compile("date.any").unwrap();
    /// let raw_result = date_pat.match_raw(1, "Sat Nov 5, 1955", &MatchEncoder::JSON).unwrap();
    /// let parsed_result : JSONMatchResult = serde_json::from_slice(raw_result.as_bytes()).unwrap();
    /// ```
    /// 
    pub fn match_raw<'pat>(&'pat mut self, start : usize, input : &str, encoder : &MatchEncoder) -> Result<RawMatchResult<'pat>, RosieError> {
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
    /// # use rosie_rs::*;
    /// let date_pat = Pattern::compile("date.any").unwrap();
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

//A variant on maybe_owned::MaybeOwned, except it can either be a String or an &str.
//TODO: Roll this out into a stand-alone crate
#[derive(Debug)]
enum MaybeOwnedString<'a> {
    Owned(String),
    Borrowed(&'a str),
}

impl MaybeOwnedString<'_> {
    pub fn as_str(&self) -> &str {
        match self {
            MaybeOwnedString::Owned(the_string) => the_string.as_str(),
            MaybeOwnedString::Borrowed(the_str) => the_str
        }
    }
}

/// Represents the results of a match operation, performed by [Pattern::match_str]
/// 
//**TODO** I feel like a more caller-friendly interface is possible; i.e. the ability to specify sub-patterns with a "path"
#[derive(Debug)]
pub struct MatchResult<'a> {
    pat_name : String,
    start : usize,
    end : usize,
    data : MaybeOwnedString<'a>,
    subs : Vec<MatchResult<'a>>
}

impl <'a>MatchResult<'a> {

    //This function is a port from the python code here: https://gitlab.com/rosie-community/clients/python/-/blob/master/rosie/decode.py
    fn from_bytes_buffer<'input>(input : &'input str, match_buffer : &mut &[u8], existing_start_pos : Option<usize>) -> MatchResult<'input> {

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
            MaybeOwnedString::Owned(String::from_utf8(data_chars.to_vec()).unwrap())
        } else {
            let (_, match_data) = input.split_at(start_position-1);
            MaybeOwnedString::Borrowed(match_data)
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
        if let MaybeOwnedString::Borrowed(match_data) = data {
            let (new_data_ref, _) = match_data.split_at(end_position - start_position);
            data = MaybeOwnedString::Borrowed(new_data_ref);
        }
        
        MatchResult{
            pat_name : pattern_name,
            start : start_position,
            end : end_position,
            data : data,
            subs : subs
        }
    }
    fn from_byte_match_result<'input>(input : &'input str, src_result : RawMatchResult) -> MatchResult<'input> {
        let mut data_buf_ref = src_result.as_bytes();
        MatchResult::from_bytes_buffer(input, &mut data_buf_ref, None)
    }
    fn new_no_match() -> MatchResult<'static> {
        MatchResult{
            pat_name : "".to_string(),
            start : 0,
            end : 0,
            data : MaybeOwnedString::Borrowed(""),
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
    /// Returns the subset of the input that was matched by the pattern
    pub fn matched_str(&self) -> &str {
        self.data.as_str()
    }
    //GOAT, Make the below work, once I've eliminated the MaybeOwned string inside MatchResult
    // /// Returns the subset of the input that was matched by the pattern, consuming the MatchResult
    // pub fn into_matched_str(self) -> &'a str {
    //     self.data.into_str()
    // }
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
    /// Returns an [Iterator] over all of the sub-patterns withing this matched pattern
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
    /// A simple test to make sure we can do a basic match with the default singleton engine
    fn default_engine() {

        let pat = Pattern::compile("{ [H][^]* }").unwrap();
        let result = pat.match_str("Hello, Rosie!").unwrap();
        assert_eq!(result.matched_str(), "Hello, Rosie!");

        if Rosie::match_str("{ [H][^]* }", "Hello, Rosie!") {
            println!("GOAT YES");
        } else {
            println!("GOAT NO");
        }

    }

    #[test]
    /// Tests the interfaces to explicitly manage RosieEngines
    fn explicit_engine() {

        //Create the engine and check that it was sucessful
        let mut engine = RosieEngine::new(None).unwrap();

        //Make sure we can get the engine config
        let _ = engine.config_as_json().unwrap();

        //Check that we can get the library path, and then set it, if needed
        let lib_path = engine.lib_path().unwrap();
        println!("lib_path = {}", lib_path.display());
        let new_lib_path = lib_path.to_path_buf(); //We copy the Path, so we can drop the one that's borrowed from the engine in order to mutate the engine safely
        engine.set_lib_path(new_lib_path).unwrap();

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
        //println!("{}", message.as_str());

        //Recompile a pattern expression and match it against a matching input using match_pattern_raw
        let mut pat = engine.compile("{[012][0-9]}", None).unwrap();
        let raw_match_result = pat.match_raw(1, "21", &MatchEncoder::Bool).unwrap();
        //Validate that we can't access the engine while our raw_match_result is in use.
        //TODO: Implement a TryBuild harness in order to ensure the two lines below will not compile together, although each will compile separately.
        // assert!(engine.config_as_json().is_ok());
        assert_eq!(raw_match_result.did_match(), true);
        assert!(raw_match_result.time_elapsed_matching() <= raw_match_result.time_elapsed_total()); //A little lame as tests go, but validates they are called at least.

        //Now try the match with the high-level match_str call
        let match_result = pat.match_str("21").unwrap();
        assert_eq!(match_result.pat_name_str(), "*");
        assert_eq!(match_result.matched_str(), "21");
        assert_eq!(match_result.start(), 1);
        assert_eq!(match_result.end(), 3);
        assert_eq!(match_result.sub_pat_count(), 0);

        //Try it against non-matching input, and make sure we get no match
        let match_result = pat.match_str("99").unwrap();
        assert_eq!(match_result.did_match(), false);

        //Test the trace function, and make sure we get a reasonable result
        let mut trace = RosieMessage::empty();
        assert!(pat.trace(1, "21", TraceFormat::Condensed, &mut trace).is_ok());
        assert!(trace.as_str().len() > 0);
        //println!("{}", trace.as_str());

        //Test loading a package from a string
        let pkg_name = engine.load_pkg_from_str("package two_digit_year\n\nyear = {[012][0-9]}", None).unwrap();
        assert_eq!(pkg_name.as_str(), "two_digit_year");

        //Test loading a package from a file
        let rpl_file = Path::new(engine.lib_path().unwrap()).join("date.rpl");
        let pkg_name = engine.load_pkg_from_file(rpl_file.to_str().unwrap(), None).unwrap();
        assert_eq!(pkg_name.as_str(), "date");

        //Test importing a package
        let pkg_name = engine.import_pkg("net", None, None).unwrap();
        assert_eq!(pkg_name.as_str(), "net");

        //Q-06.02 QUESTION ROSIE FEATURE REQUEST.  It would be nice if one of the "date.any" patterns could sucessfully match: "Sat., Nov. 5, 1955"

        //Test matching a pattern with some recursive sub-patterns
        let mut date_pat = engine.compile("date.us_long", None).unwrap();
        let match_result = date_pat.match_str("Saturday, Nov 5, 1955").unwrap();
        assert_eq!(match_result.pat_name_str(), "us_long");
        assert_eq!(match_result.matched_str(), "Saturday, Nov 5, 1955");
        assert_eq!(match_result.start(), 1);
        assert_eq!(match_result.end(), 22);
        assert_eq!(match_result.sub_pat_count(), 4);
        let sub_match_pat_names : Vec<&str> = match_result.sub_pat_iter().map(|result| result.pat_name_str()).collect();
        assert!(sub_match_pat_names.contains(&"day_name"));
        assert!(sub_match_pat_names.contains(&"month_name"));
        assert!(sub_match_pat_names.contains(&"day"));
        assert!(sub_match_pat_names.contains(&"year"));

        //Verify that the RawMatchResults from two different compiled patterns don't interfere with each other
        //Also test the JSONPretty encoder while we're at it
        engine.load_expression_deps("time.any", None).unwrap();
        let mut time_pat = engine.compile("time.any", None).unwrap();
        let date_raw_match_result = date_pat.match_raw(1, "Saturday, Nov 5, 1955", &MatchEncoder::JSONPretty).unwrap();
        let time_raw_match_result = time_pat.match_raw(1, "2:21 am", &MatchEncoder::JSONPretty).unwrap();
        assert!(date_raw_match_result.as_str() != time_raw_match_result.as_str());
        //NOTE: I know these checks might break with perfectly legal changes to JSON formatting, but at least they
        // will flag it, so a human can take a look and ensure something more fundamental didn't break.
        assert_eq!(date_raw_match_result.as_str().len(), 625);
        assert_eq!(time_raw_match_result.as_str().len(), 453);

    }

    #[test]
    /// Tests a whole bunch of threads all doing compiling and matching at the same time
    fn thread_stress() {

        const NUM_THREADS : usize = 1; //GOAT, this should be 100
        const NUM_ITERATIONS : usize = 100; //Each iteration includes a compile
        const NUM_MATCHES : usize = 500; //Number of matches to perform each iteration

        let mut thread_handles = vec![];

        for thread_idx in 0..NUM_THREADS {
            let handle = thread::spawn(move || {

                let mut rng = Pcg64::seed_from_u64(thread_idx.try_into().unwrap()); //non-cryptographic random used for repeatability

                for _ in 0..NUM_ITERATIONS{

                    let pat_idx : u8 = rng.gen_range(0..2);
                    let pat_expr = match pat_idx {
                        0 => "{ [H][^]* }",
                        1 => "date.any",
                        2 => "time.any",
                        _ => panic!()
                    };

                    let pat = Pattern::compile(pat_expr).unwrap();

                    for _ in 0..NUM_MATCHES {

                        let str_idx : u8 = rng.gen_range(0..2);
                        let str_val = match str_idx {
                            0 => "Hello, Rosie!",
                            1 => "Saturday, Nov 5, 1955",
                            2 => "2:21 am",
                            _ => panic!()
                        };
    
                        let result = pat.match_str(str_val).unwrap();
    
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
