
use std::ptr;
use std::str;
use std::convert::{TryFrom};
use std::path::{Path};
use std::rc::{Rc};

use rosie_sys::{*};
use crate::{RosieMessage, MatchResult, librosie_init};

//A wrapper around an EnginePtr so we can implement Drop
//NOTE: Only pub within this crate
pub struct RawEngine<'a>(EnginePtr<'a>);

//Give librosie a chance to clean up the engine
impl Drop for RawEngine<'_> {
    fn drop(&mut self) {
        unsafe{ rosie_finalize(self.0); }
    }
}

/// The Rust object representing a Rosie engine.  Used when direct access to rosie engines is desired.
/// 
/// **NOTE**: RosieEngines are not internally thread-safe, but you may create more than one RosieEngine in
/// order to use multiple threads.
/// 
// TODO: This is a 3-level indirection because the RawEngine itself is a ptr.  Maybe this can be improved
// if this turns out to be a bottleneck.);
pub struct RosieEngine<'a>(Rc<RawEngine<'a>>);

impl RosieEngine<'_> {
    // Private convenience to get the EnginePtr for the RosieEngine
    fn ptr(&self) -> EnginePtr<'_> {
        self.0.0
    }
    /// Creates a new RosieEngine.
    /// 
    /// If this operation fails then an error message can be obtained by passing a mutable reference to a [RosieMessage].
    pub fn new(messages : Option<&mut RosieMessage>) -> Result<Self, RosieError> {
        
        //Make sure librosie is initialized.  This is basically a noop if it is
        librosie_init::<&Path>(None);

        let mut message_buf = RosieString::empty();

        let engine_ptr = unsafe { rosie_new(&mut message_buf) };

        if let Some(result_message) = messages {
            result_message.0.manual_drop(); //We're overwriting the string that was there
            result_message.0 = message_buf;
        } else {
            message_buf.manual_drop();
        }

        if engine_ptr.e as *const _ != ptr::null() {
            Ok(RosieEngine(Rc::new(RawEngine(engine_ptr))))
        } else {
            Err(RosieError::MiscErr)
        }
    }
    /// Returns the file-system path to the directory containing the standard pattern library used by the RosieEngine.
    //GOAT, should return a Path.
    pub fn lib_path(&self) -> Result<&str, RosieError> {

        let mut path_rosie_string = RosieString::empty();
        
        let result_code = unsafe { rosie_libpath(self.ptr(), &mut path_rosie_string) };

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
        
        let result_code = unsafe { rosie_libpath(self.ptr(), &mut path_rosie_string) };

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

        let result_code = unsafe { rosie_alloc_limit(self.ptr(), &mut new_limit, &mut usage) };

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

        let result_code = unsafe { rosie_alloc_limit(self.ptr(), &mut new_limit_mut, &mut usage) };

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

        let result_code = unsafe { rosie_alloc_limit(self.ptr(), &mut new_limit, &mut usage) };

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

        let result_code = unsafe { rosie_config(self.ptr(), &mut config_buf) };

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

        let result_code = unsafe { rosie_compile(self.ptr(), &expression_rosie_string, &mut pat_idx, &mut message_buf) };

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
        let result_code = unsafe { rosie_free_rplx(self.ptr(), pattern_id.0) };

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

        let result_code = unsafe{ rosie_match(self.ptr(), pattern_id.0, i32::try_from(start).unwrap(), encoder.as_bytes().as_ptr(), &input_rosie_string, &mut match_result) }; 

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
        let result_code = unsafe { rosie_trace(self.ptr(), pattern_id.0, i32::try_from(start).unwrap(), format.as_bytes().as_ptr(), &input_rosie_string, &mut matched, &mut trace.0) };

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

        let result_code = unsafe { rosie_load(self.ptr(), &mut ok, &rpl_text_rosie_string, &mut pkg_name, &mut message_buf) };

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

        let result_code = unsafe { rosie_loadfile(self.ptr(), &mut ok, &file_name_rosie_string, &mut pkg_name, &mut message_buf) };

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

        let result_code = unsafe { rosie_import(self.ptr(), &mut ok, &in_pkg_name, &in_alias, &mut out_pkg_name, &mut message_buf) };
        
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

pub trait PrivateRosieEngine {
    fn clone_private(&self) -> Self;
}

impl PrivateRosieEngine for RosieEngine<'_> {
    fn clone_private(&self) -> Self {
        Self(self.0.clone())
    }
}

/// An index that identifies a compiled pattern within a [RosieEngine].
/// 
/// PatternIDs are created by [compile_pattern](RosieEngine::compile_pattern), and the patterns they represent can be freed with [free_pattern](RosieEngine::free_pattern).
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct PatternID(i32);