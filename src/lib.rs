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
//! ## Example Usage
//! ```
//! use rosie_rs::*;
//! let mut engine = RosieEngine::new(None).unwrap();
//! engine.import_pkg("date", None, None);
//! 
//! let date_pat = engine.compile_pattern("date.us_long", None).unwrap();
//! let match_result = engine.match_pattern(date_pat, 1, "Saturday, Nov 5, 1955").unwrap();
//! ```
//! 

use std::slice::Iter;
use std::str;
use std::convert::{TryFrom, TryInto};
use std::path::{Path, PathBuf};
use std::fs;
use std::cell::RefCell;
use std::sync::Mutex;

use once_cell::sync::Lazy; // TODO: As soon as std::sync::SyncLazy is pushed to stable, we will migrate there and eliminate this dependency

extern crate rosie_sys;
use rosie_sys::{*};

//Public re-exports
pub use rosie_sys::RosieError;
pub use rosie_sys::MatchEncoder;
pub use rosie_sys::TraceFormat;
pub use rosie_sys::RawMatchResult;

/// Functionality to access [RosieEngine]s directly
pub mod engine;

use engine::{*};

//GOAT, Go back to my changes inside librosie, and use an atomic type for my path pointer

//Global to track the state of librosie
static LIBROSIE_INITIALIZED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

//Global per-thread singleton engines
//NOTE: The thread_local! macro forces us to have an initialization check (which we probably want anyway) but also
// a RefCell (which we could probably get by without).  I don't think this matters in light of the Rosie usage
// patterns, but if I'm wrong and we need this access to be faster, we can shave a few nanoseconds by implementing
// thread_local access ourselves.  Unfortunately the direct accessor for the LLVM `thread_local` attribute isn't
// stabilized yet.  https://github.com/rust-lang/rust/issues/29594  This blog has a work-around, but it would be
// fragile because of the need to inline across langauges.  It's a good read anyway.
// https://matklad.github.io/2020/10/03/fast-thread-locals-in-rust.html
thread_local!{ static THREAD_ROSIE_ENGINE: RefCell<RosieEngine<'static>> = RefCell::new(RosieEngine::new(None).unwrap()) }

/// A buffer to obtain text from Rosie.
/// 
/// The contents of the buffer depend on the situation under which it is returned.
/// Sometimes the returned text is formatted as JSON and other times it is a human-readable message.
/// 
/// # Example
/// ```
/// # use rosie_rs::*;
/// # let mut engine = RosieEngine::new(None).unwrap();
/// let mut message = RosieMessage::empty();
/// engine.compile_pattern("invalid pattern", Some(&mut message));
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

/// GOAT, document Pattern
#[derive(Clone)]
pub struct Pattern<'a> {
    engine : RosieEngine<'a>,
    id : i32
}

impl Pattern<'_> {

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

/// Represents the results of a match operation, performed by [match_pattern](RosieEngine::match_pattern)
/// 
/// **TODO** Need better documentation here, but I feel like this belongs in the higher-level crate, and
/// I believe a more caller-friendly interface is possible.
/// 
#[derive(Debug)]
pub struct MatchResult<'a> {
    pat_name : String,
    start : usize,
    end : usize,
    data : MaybeOwnedString<'a>,
    subs : Vec<MatchResult<'a>>
}

impl MatchResult<'_> {

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
    pub fn did_match(&self) -> bool {
        if self.start == 0 && self.end == 0 {
            false
        } else {
            true
        }
    }
    pub fn pat_name_str(&self) -> &str {
        self.pat_name.as_str()
    }
    pub fn matched_str(&self) -> &str {
        self.data.as_str()
    }
    pub fn start(&self) -> usize {
        self.start
    }
    pub fn end(&self) -> usize {
        self.end
    }
    pub fn sub_pat_count(&self) -> usize {
        self.subs.len()
    }
    pub fn sub_pat_iter(&self) -> Iter<'_, MatchResult> {
        self.subs.iter()
    }
}

#[cfg(test)]
mod tests {
    use crate::{*};
    use std::thread;
    use std::sync::mpsc;

    #[test]
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
    fn default_engine() {
        //GOAT
    }

    #[test]
    fn explicit_engine() {

        //GOAT.  Create multi-threaded test(s)
        //
        //GOAT.  Make a multi-threaded stress-test that instantiates a large number of threads
        //
        //GOAT.  Make direct-engine API
        //GOAT.  Make "default-engine" API
        //  Take stock of what config entry points exist.  Possibly I don't need a way to access the default engine directly, which is better.
        //      If it does make sense to access the default engine:
        //          Get default Engine (for a given thread)
        //          Config sync across the different threads
        //  Compile pattern into a wrapped object.
        //  Match pattern

        //Create the engine and check that it was sucessful
        let mut engine = RosieEngine::new(None).unwrap();

        //Make sure we can get the engine config
        let _ = engine.config_as_json().unwrap();

        //Check that we can get the library path, and then set it, if needed
        let lib_path = engine.lib_path().unwrap();
        //println!("{}", lib_path);
        let new_lib_path = lib_path.to_string(); //We need a copy of the string, so we can mutate the engine safely
        engine.set_lib_path(new_lib_path.as_str()).unwrap();

        //Check the alloc limit, set it to unlimited, check the usage
        let _ = engine.mem_alloc_limit().unwrap();
        assert!(engine.set_mem_alloc_limit(0).is_ok());
        let _ = engine.mem_usage().unwrap();

        //Compile a valid rpl pattern, and confirm there is no error
        let pat_idx = engine.compile_pattern("{[012][0-9]}", None).unwrap();

        //Make sure we can sucessfully free the pattern
        assert!(engine.free_pattern(pat_idx).is_ok());
        
        //Try to compile an invalid pattern (syntax error), and check the error and error message
        let mut message = RosieMessage::empty();
        let compile_result = engine.compile_pattern("year = bogus", Some(&mut message));
        assert!(compile_result.is_err());
        assert!(message.len() > 0);
        //println!("{}", message.as_str());

        //Recompile a pattern expression and match it against a matching input using match_pattern_raw
        let pat_idx = engine.compile_pattern("{[012][0-9]}", None).unwrap();
        let raw_match_result = engine.match_pattern_raw(pat_idx, 1, "21", &MatchEncoder::Bool).unwrap();
        //Validate that we can't access the engine while our raw_match_result is in use.
        //TODO: Implement a TryBuild harness in order to ensure the two lines below will not compile together, although each will compile separately.
        // assert!(engine.config_as_json().is_ok());
        assert_eq!(raw_match_result.did_match(), true);
        assert!(raw_match_result.time_elapsed_matching() <= raw_match_result.time_elapsed_total()); //A little lame as tests go, but validates they are called at least.

        //Now try the match with the high-level match_pattern call
        let match_result = engine.match_pattern(pat_idx, 1, "21").unwrap();
        assert_eq!(match_result.pat_name_str(), "*");
        assert_eq!(match_result.matched_str(), "21");
        assert_eq!(match_result.start(), 1);
        assert_eq!(match_result.end(), 3);
        assert_eq!(match_result.sub_pat_count(), 0);

        //Try it against non-matching input, and make sure we get no match
        let match_result = engine.match_pattern(pat_idx, 1, "99").unwrap();
        assert_eq!(match_result.did_match(), false);

        //Test the trace function, and make sure we get a reasonable result
        let mut trace = RosieMessage::empty();
        assert!(engine.trace_pattern(pat_idx, 1, "21", TraceFormat::Condensed, &mut trace).is_ok());
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
        let date_pat_idx = engine.compile_pattern("date.us_long", None).unwrap();
        let match_result = engine.match_pattern(date_pat_idx, 1, "Saturday, Nov 5, 1955").unwrap();
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

    }

    #[test]
    fn multi_threaded_default_engine() {

        let (tx, rx) = mpsc::channel();

        let handle = thread::spawn(move || {

            THREAD_ROSIE_ENGINE.with(move |engine_refcell| {

                for _ in 0..1 {
                    let pat_idx = engine_refcell.borrow_mut().compile_pattern("{[012][0-9]}", None).unwrap();
                    tx.send(pat_idx).unwrap();    
                }

            });
        });


        THREAD_ROSIE_ENGINE.with(move |engine_refcell| {

            for received in rx {
//                println!("Got: {}", received.0); GOAT

                let pat_idx = engine_refcell.borrow_mut().compile_pattern("{[012][0-9]}", None).unwrap();
//                println!("main: {}", pat_idx.0);
        
            }
        
        });


        handle.join().unwrap();
        
        //GOAT
    }

    #[test]
    fn thread_stress() {
        //GOAT
    }

}
//More LibRosie questions:
//1. Understand the difference between an expression and a "block", as in the last 6 native functions I haven't tried yet
//  my hypothesis is that a block is a bunch of patterns in the form "name = expression", and an expression is a single
//  pattern, or a single pattern name.
//
//2. Understand the meaning of "deps", "refs" & "parsetree"s, as they're used in the last 6 functions I'm not calling.
//
