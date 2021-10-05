#![crate_name = "rosie_rs"]

//! # rosie-rs Overview
//! This crate implements Rust low-level (but still safe) access to the [**Rosie**](https://rosie-lang.org/about/) matching engine for the [**Rosie Pattern Language**](https://gitlab.com/rosie-pattern-language/rosie/-/blob/master/README.md)\(`rpl`\).
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

use std::ptr;
use std::slice::Iter;
use std::str;
use std::convert::{TryFrom, TryInto};
use std::path::{Path, PathBuf};

extern crate rosie_sys;
use rosie_sys::{*};

//Public re-exports
pub use rosie_sys::RosieError;
pub use rosie_sys::MatchEncoder;
pub use rosie_sys::TraceFormat;
pub use rosie_sys::RawMatchResult;

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

/// The Rust object representing a Rosie engine.  
/// 
/// **NOTE**: RosieEngines are not internally thread-safe, but you may create more than one RosieEngine in order to use multiple threads.
pub struct RosieEngine<'a>(EnginePtr<'a>);

//Give librosie a chance to clean up the engine
impl Drop for RosieEngine<'_> {
    fn drop(&mut self) {
        unsafe{ rosie_finalize(self.0); }
    }
}

impl RosieEngine<'_> {
    /// Creates a new RosieEngine.
    /// 
    /// If this operation fails then an error message can be obtained by passing a mutable reference to a [RosieMessage].
    pub fn new(messages : Option<&mut RosieMessage>) -> Result<Self, RosieError> {
        
        let mut message_buf = RosieString::empty();

        let engine_ptr = unsafe { rosie_new(&mut message_buf) };

        if let Some(result_message) = messages {
            result_message.0.manual_drop(); //We're overwriting the string that was there
            result_message.0 = message_buf;
        } else {
            message_buf.manual_drop();
        }

        if engine_ptr.e as *const _ != ptr::null() {
            Ok(RosieEngine(engine_ptr))
        } else {
            Err(RosieError::MiscErr)
        }
    }
    /// Returns the file-system path to the directory containing the standard pattern library used by the RosieEngine.
    //GOAT, should return a Path
    pub fn lib_path(&self) -> Result<&str, RosieError> {

        let mut path_rosie_string = RosieString::empty();
        
        let result_code = unsafe { rosie_libpath(self.0, &mut path_rosie_string) };

        if result_code == 0 {
            Ok(path_rosie_string.into_str())
        } else {
            Err(RosieError::from(result_code))
        }
    }
    /// Sets the directory to use when loading packages from the standard pattern library.
    /// 
    /// This will affect the behavior of [import_pkg](RosieEngine::import_pkg), as well as any other operations that load rpl code using the `import` directive.
    //GOAT, filename should be a AsRef<Path>
    pub fn set_lib_path(&mut self, new_path : &str) -> Result<(), RosieError> {

        let mut path_rosie_string = RosieString::from_str(new_path);

        //Q-03.09.A QUESTION FOR A ROSIE EXPERT: Can this function set multiple paths?  If so, how do I clear them?
        
        let result_code = unsafe { rosie_libpath(self.0, &mut path_rosie_string) };

        if result_code == 0 {
            Ok(())
        } else {
            Err(RosieError::from(result_code))
        }
    }
    /// Returns the engine's allocation limit, in bytes.
    /// 
    /// 0 indicates the absence of an allocation limit and therefore unlimited allocations are permitted.
    pub fn mem_alloc_limit(&self) -> Result<usize, RosieError> {
        let mut new_limit : i32 = -1;
        let mut usage : i32 = 0;

        let result_code = unsafe { rosie_alloc_limit(self.0, &mut new_limit, &mut usage) };

        if result_code == 0 {
            Ok(usize::try_from(new_limit).unwrap())
        } else {
            Err(RosieError::from(result_code))
        }
    }
    /// Sets the engine's allocation limit, in bytes.  
    /// 
    /// Passing 0 will remove the allocation limit and thus permit the engine to make unlimited memory allocations.
    /// 
    /// **NOTE**: The allocation limit allows the engine to allocate `new_limit` bytes **Above** the current memory usage.  For example,
    /// if the engine were currently using 3000 bytes, and you called this function with a `new_limit` value of 10000, then the engine
    /// would be permitted to consume 13000 bytes in total.
    /// 
    /// **NOTE**: This function will panic if the `new_limit` argument is higher than 2GB.
    pub fn set_mem_alloc_limit(&self, new_limit : usize) -> Result<(), RosieError> {
        let mut new_limit_mut = i32::try_from(new_limit).unwrap();
        let mut usage : i32 = 0;

        let result_code = unsafe { rosie_alloc_limit(self.0, &mut new_limit_mut, &mut usage) };

        if result_code == 0 {
            Ok(())
        } else {
            Err(RosieError::from(result_code))
        }
    }
    /// Returns the current memory usage of the RosieEngine, in bytes.
    pub fn mem_usage(&self) -> Result<usize, RosieError> {
        let mut new_limit : i32 = -1;
        let mut usage : i32 = 0;

        let result_code = unsafe { rosie_alloc_limit(self.0, &mut new_limit, &mut usage) };

        if result_code == 0 {
            Ok(usize::try_from(usage).unwrap())
        } else {
            Err(RosieError::from(result_code))
        }
    }
    //PUNT. QUESTION: Does it make sense to parse this json into a structure that's easier to query?  The API client can parse
    //it easily enough, so probably better to keep the crate dependencies lower.
    /// Returns a [RosieMessage] containing a JSON-formatted structure of Rosie configuration parameters.
    pub fn config_as_json(&self) -> Result<RosieMessage, RosieError> {

        let mut config_buf = RosieString::empty();

        let result_code = unsafe { rosie_config(self.0, &mut config_buf) };

        let config_message = RosieMessage(config_buf);

        if result_code == 0 {
            Ok(config_message)
        } else {
            Err(RosieError::from(result_code))
        }
    }
    /// Compiles the specified expression, returning a [PatternID] that can then be used to match that expression.
    /// 
    /// The expression may be either the name of a previously loaded `rpl` pattern, or it may be a raw `rpl` expression.
    /// 
    /// # Examples
    /// ```
    /// # use rosie_rs::*;
    /// # let mut engine = RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", None, None);
    /// let date_pat = engine.compile_pattern("date.us_long", None).unwrap();
    /// ```
    /// 
    /// ```
    /// # use rosie_rs::*;
    /// # let mut engine = RosieEngine::new(None).unwrap();
    /// let two_digit_year_pat = engine.compile_pattern("{[012][0-9]}", None).unwrap();
    /// ```
    /// 
    pub fn compile_pattern(&mut self, expression : &str, messages : Option<&mut RosieMessage>) -> Result<PatternID, RosieError> {

        let mut pat_idx : i32 = 0;
        let mut message_buf = RosieString::empty();

        let expression_rosie_string = RosieString::from_str(expression);

        let result_code = unsafe { rosie_compile(self.0, &expression_rosie_string, &mut pat_idx, &mut message_buf) };

        if let Some(result_message) = messages {
            result_message.0.manual_drop(); //We're overwriting the string that was there
            result_message.0 = message_buf;
        } else {
            message_buf.manual_drop();
        }
        
        if result_code == 0 {
            if pat_idx > 0 {
                Ok(PatternID(pat_idx))
            } else {
                Err(RosieError::PatternError)
            }
        } else {
            Err(RosieError::from(result_code))
        }
    }
    /// Frees a pattern that was previously compiled with [compile_pattern](RosieEngine::compile_pattern).
    pub fn free_pattern(&mut self, pattern_id : PatternID) -> Result<(), RosieError> {
        let result_code = unsafe { rosie_free_rplx(self.0, pattern_id.0) };

        if result_code == 0 {
            Ok(())
        } else {
            Err(RosieError::from(result_code))
        }
    }

    /// Matches the specified `pattern_id` in the specified `input` string, beginning from the `start` index, using the specified `encoder`.
    /// 
    /// Returns a [RawMatchResult] or an error code if a problem was encountered.  This is a lower-level API than [match_pattern](RosieEngine::match_pattern),
    /// and there are two situations where you might want to use it:
    /// - If you want to the output from a particular [MatchEncoder]
    /// - If you need the fastest possible match performance, using the [Bool](MatchEncoder::Bool) encoder
    /// 
    /// **NOTE**: The returned [RawMatchResult] takes a mutable borrow of the `engine`, and thus the engine cannot be accessed
    /// while the RawMatchResult is in use.  Copying the data from the RawMatchResult will allow the `engine` to be released.
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
    /// let mut engine = RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", None, None);
    /// let date_pat = engine.compile_pattern("date.any", None).unwrap();
    /// let raw_result = engine.match_pattern_raw(date_pat, 1, "Sat Nov 5, 1955", &MatchEncoder::JSON).unwrap();
    /// let parsed_result : JSONMatchResult = serde_json::from_slice(raw_result.as_bytes()).unwrap();
    /// ```
    pub fn match_pattern_raw<'engine>(&'engine mut self, pattern_id : PatternID, start : usize, input : &str, encoder : &MatchEncoder) -> Result<RawMatchResult<'engine>, RosieError> {

        if start < 1 || start > input.len() {
            return Err(RosieError::ArgError);
        }

        let input_rosie_string = RosieString::from_str(input);
        let mut match_result = RawMatchResult::empty();

        let result_code = unsafe{ rosie_match(self.0, pattern_id.0, i32::try_from(start).unwrap(), encoder.as_bytes().as_ptr(), &input_rosie_string, &mut match_result) }; 

        if result_code == 0 {
            Ok(match_result)
        } else {
            Err(RosieError::from(result_code))
        }
    }

    /// Matches the specified `pattern_id` in the specified `input` string, beginning from the `start` index.
    /// 
    /// Returns a [MatchResult] if a match was found, otherwise returns an appropriate error code.
    /// 
    /// **NOTE**: The values for `start` are 1-based.  Meaning passing 1 will begin the match from the beginning of the input, and
    /// passing 0 (zero) is an error.
    pub fn match_pattern<'input>(&mut self, pattern_id : PatternID, start : usize, input : &'input str) -> Result<MatchResult<'input>, RosieError> {
        
        let raw_match_result = self.match_pattern_raw(pattern_id, start, input, &MatchEncoder::Byte)?;
                
        if raw_match_result.did_match() {
            Ok(MatchResult::from_byte_match_result(input, raw_match_result))
        } else {
            Ok(MatchResult::new_no_match())
        }
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
    /// # let mut engine = RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", None, None);
    /// let date_pat = engine.compile_pattern("date.any", None).unwrap();
    /// 
    /// let mut trace = RosieMessage::empty();
    /// let did_match = engine.trace_pattern(date_pat, 1, "Sat. Nov. 5, 1955", TraceFormat::Condensed, &mut trace).unwrap();
    /// println!("{}", trace.as_str());
    /// ```
    /// 
    pub fn trace_pattern(&mut self, pattern_id : PatternID, start : usize, input : &str, format : TraceFormat, trace : &mut RosieMessage) -> Result<bool, RosieError> {

        if start < 1 || start > input.len() {
            return Err(RosieError::ArgError);
        }
        
        let input_rosie_string = RosieString::from_str(input);
        let mut matched : i32 = -1;

        trace.0.manual_drop(); //We'll be overwriting whatever string was already there

        //NOTE: valid trace_style arguments are: "json\0", "full\0", and "condensed\0"
        let result_code = unsafe { rosie_trace(self.0, pattern_id.0, i32::try_from(start).unwrap(), format.as_bytes().as_ptr(), &input_rosie_string, &mut matched, &mut trace.0) };

        if result_code == 0 {
            if matched == 1 {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(RosieError::from(result_code))
        }
    }
    
    /// Loads a package of `rpl` patterns from the spcified text.
    /// 
    /// Returns a [RosieMessage] containing the name of the package that was loaded.
    /// 
    /// **NOTE**: The specified text must contain a `package` declaration, to provide the name of the package in the pattern namespace.
    /// 
    pub fn load_pkg_from_str(&mut self, rpl_text : &str, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {
        
        let rpl_text_rosie_string = RosieString::from_str(rpl_text);
        let mut pkg_name = RosieString::empty();
        let mut message_buf = RosieString::empty();
        let mut ok : i32 = 0;

        let result_code = unsafe { rosie_load(self.0, &mut ok, &rpl_text_rosie_string, &mut pkg_name, &mut message_buf) };

        if let Some(result_message) = messages {
            result_message.0.manual_drop(); //We're overwriting the string that was there
            result_message.0 = message_buf;
        } else {
            message_buf.manual_drop();
        }

        if result_code == 0 {
            if pkg_name.is_valid() && ok > 0 {
                Ok(RosieMessage(pkg_name))
            } else {
                Err(RosieError::PackageError)
            }
        } else {
            Err(RosieError::from(result_code))
        }
    }

    /// Loads a package of `rpl` patterns from the spcified file.
    /// 
    /// Returns a [RosieMessage] containing the name of the package that was loaded.
    /// 
    /// **NOTE**: The file must contain a `package` declaration, to provide the name of the package in the pattern namespace.
    /// 
    //GOAT, filename should be a AsRef<Path>
    pub fn load_pkg_from_file(&mut self, file_name : &str, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {

        let file_name_rosie_string = RosieString::from_str(file_name);
        let mut pkg_name = RosieString::empty();
        let mut message_buf = RosieString::empty();
        let mut ok : i32 = 0;

        let result_code = unsafe { rosie_loadfile(self.0, &mut ok, &file_name_rosie_string, &mut pkg_name, &mut message_buf) };

        if let Some(result_message) = messages {
            result_message.0.manual_drop(); //We're overwriting the string that was there
            result_message.0 = message_buf;
        } else {
            message_buf.manual_drop();
        }

        if result_code == 0 {
            if pkg_name.is_valid() && ok > 0 {
                Ok(RosieMessage(pkg_name))
            } else {
                Err(RosieError::PackageError)
            }
        } else {
            Err(RosieError::from(result_code))
        }
    }

    /// Imports a package from the pattern library
    /// 
    /// Returns a [RosieMessage] containing the name of the package that was loaded, according to the package's `package` declaration.
    /// 
    /// Optionally, an `alias` may be provided, in order to specify the name uses by other patterns to access the
    /// patterns from this package.  An `alias` may be useful for influencing the the `pat_name` that is part of
    /// the [MatchResult] and [RawMatchResult] structures.
    /// 
    /// **NOTE**: Usually, the returned [RosieMessage] will match the `pkg_name` argument, but this will not always be the case.
    /// This function searches all directories that are part of the engine's `lib_path` (set using [lib_path](RosieEngine::lib_path)),
    /// searching for files named '`pkg_name.rpl`'.  When it finds the relevant `.rpl` file, the file is loaded and parsed,
    /// and the package name from the package's `package` declaration is returned.  It is a best practice for the filename to match the
    /// `package` declaration, but it is not enforced or required.
    /// 
    /// # Examples
    /// Without an alias:
    /// ```
    /// # use rosie_rs::*;
    /// # let mut engine = RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", None, None);
    /// let date_pat = engine.compile_pattern("date.any", None).unwrap();
    /// ```
    /// With an alias:
    /// ```
    /// # use rosie_rs::*;
    /// # let mut engine = RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", Some("special_date"), None);
    /// let date_pat = engine.compile_pattern("special_date.any", None).unwrap();
    /// ```
    /// 
    
    pub fn import_pkg(&mut self, pkg_name : &str, alias : Option<&str>, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {

        let in_pkg_name = RosieString::from_str(pkg_name);
        let in_alias = match alias {
            Some(alias_str) => RosieString::from_str(alias_str),
            None => RosieString::from_str(pkg_name)
        };
        let mut out_pkg_name = RosieString::empty();
        let mut message_buf = RosieString::empty();
        let mut ok : i32 = 0;

        let result_code = unsafe { rosie_import(self.0, &mut ok, &in_pkg_name, &in_alias, &mut out_pkg_name, &mut message_buf) };
        
        if let Some(result_message) = messages {
            result_message.0.manual_drop(); //We're overwriting the string that was there
            result_message.0 = message_buf;
        } else {
            message_buf.manual_drop();
        }

        if result_code == 0 {
            if out_pkg_name.is_valid() && ok > 0 {
                Ok(RosieMessage(out_pkg_name))
            } else {
                out_pkg_name.manual_drop();
                Err(RosieError::PackageError)
            }
        } else {
            out_pkg_name.manual_drop();
            Err(RosieError::from(result_code))
        }
    }
}

/// An index that identifies a compiled pattern within a [RosieEngine].
/// 
/// PatternIDs are created by [compile_pattern](RosieEngine::compile_pattern), and the patterns they represent can be freed with [free_pattern](RosieEngine::free_pattern).
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct PatternID(i32);

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
fn rosie_engine() {

    //GOAT, This doesn't belong in this test.  We have to see how we can init this inside a singleton engine.
    if let Some(rosie_home_dir) = rosie_home_default() {
        //GOAT, we definitely want to make sure this path is valid before calling rosie_home_init(), because rosie_home_init() will take whatever we're selling
        let mut message_buf = RosieString::empty();
        unsafe{ rosie_home_init(&RosieString::from_str(&rosie_home_dir), &mut message_buf) };
        println!("GOAT Rosie_home {}", rosie_home_dir);
    };

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
    let rpl_file = PathBuf::from(engine.lib_path().unwrap()).join("date.rpl");
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

//More LibRosie questions:
//1. Understand the difference between an expression and a "block", as in the last 6 native functions I haven't tried yet
//  my hypothesis is that a block is a bunch of patterns in the form "name = expression", and an expression is a single
//  pattern, or a single pattern name.
//
//2. Understand the meaning of "deps", "refs" & "parsetree"s, as they're used in the last 6 functions I'm not calling.
//
