
use std::ptr;
use std::str;
use std::convert::{TryFrom};
use std::path::{Path};
use std::rc::{Rc};

use rosie_sys::{
    RosieString,
    MatchEncoder, LibRosieMatchEncoder,
    RawMatchResult, LibRosieMatchResult,
    TraceFormat, LibRosieTraceFormat,
    EnginePtr,
    //rosie_home_default,
    //rosie_new_string,
    //rosie_home_init,
    rosie_new,
    rosie_finalize,
    rosie_libpath,
    rosie_alloc_limit,
    rosie_config,
    rosie_compile,
    //rosie_free_rplx,
    //rosie_match,
    rosie_match2,
    rosie_trace,
    rosie_load,
    rosie_loadfile,
    rosie_import,
    //rosie_expression_refs,
    //rosie_expression_deps,
    rosie_import_expression_deps
};
use crate::sys_shadow::{*};
use crate::{*};

//A wrapper around an EnginePtr so we can implement Drop
//NOTE: Only pub within this crate
pub struct RawEngine(EnginePtr);

//Give librosie a chance to clean up the engine
impl Drop for RawEngine {
    fn drop(&mut self) {
        unsafe{ rosie_finalize(self.0); }
    }
}

/// The Rust object representing a Rosie engine.  Used when direct access to rosie engines is desired.
/// 
/// **NOTE**: RosieEngines are not internally thread-safe and don't implemnt [Sync] or [Send].  You may create more than one RosieEngine in
/// order to use multiple threads.  Also there is a thread-local `default_engine` accessible through [Rosie::take_thread_default_engine] and [Rosie::replace_thread_default_engine].
/// 
pub struct RosieEngine(Rc<RawEngine>);

impl RosieEngine {
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
    /// Returns the file-system paths to the directories containing the standard pattern library files used by the RosieEngine.
    pub fn lib_paths(&self) -> Result<Vec<PathBuf>, RosieError> {

        let mut paths_rosie_string = RosieString::empty();
        
        let result_code = unsafe { rosie_libpath(self.ptr(), &mut paths_rosie_string) };

        if result_code == 0 {

            let mut return_vec = vec![];

            //WARNING: Different OSs use different encodings for file paths.  Also there is no guarantee that file system paths
            // will be valid unicode (as Rust's str & String require).  There is a chance this will panic on some OSs when we
            // call into_str().

            //TODO: It's a near-certainty that this is going to break on Windows because paths routinely have ':' as part
            //of the path itself, given ':' is the drive specifier character
            for path_str in paths_rosie_string.into_str().split(":") {
                return_vec.push(PathBuf::from(path_str));
            }

            Ok(return_vec)
        } else {
            Err(RosieError::from(result_code))
        }
    }
    /// Sets the directories to use when loading packages from the standard pattern library.
    /// 
    /// This will affect the behavior of [import_pkg](RosieEngine::import_pkg), as well as [Rosie::compile]
    /// and any other operations that load rpl code using the `import` directive.
    /// 
    /// NOTE: supplied paths are not validated by this function and invalid paths will be silently accepted.
    /// 
    /// Example: Adding an additional rpl directory path
    /// ```
    /// # use rosie::*; 
    /// # use std::path::PathBuf;
    /// let mut engine = engine::RosieEngine::new(None).unwrap();
    /// let mut lib_paths = engine.lib_paths().unwrap();
    /// lib_paths.push(PathBuf::from("/tmp/temporary_rpl_dir/"));
    /// engine.set_lib_paths(&lib_paths).unwrap();
    /// ```
    pub fn set_lib_paths<P: AsRef<Path>>(&mut self, new_paths : &[P]) -> Result<(), RosieError> {

        //WARNING: Different OSs use different encodings for file paths.  Also there is no guarantee that file system paths
        // will be valid unicode (as Rust's str & String require).  There is a chance this will panic on some OSs when 
        // we try and make paths into Strings

        let mut new_paths_iter = new_paths.into_iter();
        let mut new_paths_string = if let Some(first_path) = new_paths_iter.next() {
            first_path.as_ref().to_str().unwrap().to_string()
        } else {
            "".to_string()
        };
        for new_path in new_paths_iter {
            new_paths_string.push_str(":");
            new_paths_string.push_str(new_path.as_ref().to_str().unwrap());
        }

        let mut path_rosie_string = RosieString::from_str(&new_paths_string);
        
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
    /// if the engine were currently using 3000 bytes, and you called this method with a `new_limit` value of 10000, then the engine
    /// would be permitted to consume 13000 bytes in total.
    /// 
    /// **NOTE**: This method will panic if the `new_limit` argument is higher than 2GB.
    pub fn set_mem_alloc_limit(&mut self, new_limit : usize) -> Result<(), RosieError> {
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
    /// Compiles the specified expression into a `Pattern` hosted by the `Engine`.
    /// 
    /// This is a lower-level interface than [Rosie::compile].  Expression dependencies must be manually imported using
    /// any of [import_expression_deps](RosieEngine::import_expression_deps), [RosieEngine::load_pkg_from_str],
    /// [RosieEngine::load_pkg_from_file], or [RosieEngine::import_pkg].
    /// 
    /// # Examples
    /// ```
    /// # use rosie::*;
    /// let mut engine = engine::RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", None, None);
    /// let date_pat = engine.compile("date.us_long", None).unwrap();
    /// ```
    /// 
    //INTERNAL NOTE: `compile` actually builds the pattern within the engine, so technically this is mutating the engine,
    //but conceptually this is an internal mutation, so we just take an immutable reference to the engine.
    //The exposed API doesn't allow any references to the engine internals to be retained, so this "internal mutability"
    //is safe.
    pub fn compile(&self, expression : &str, messages : Option<&mut RosieMessage>) -> Result<Pattern, RosieError> {

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
                Ok(Pattern{
                    engine : self.clone_private(),
                    id : pat_idx    
                })
            } else {
                Err(RosieError::ExpressionError)
            }
        } else {
            Err(RosieError::from(result_code))
        }
    }

    /// Parses an rpl expression and loads any dependencies 
    ///
    //INTERNAL NOTE: The call performs internal mutation on the engine, but it's safe because the mutated components can't
    // be referenced. See note on `RosieEngine::compile()`
    pub fn import_expression_deps(&self, expression : &str, messages : Option<&mut RosieMessage>) -> Result<(), RosieError> {

        let mut message_buf = RosieString::empty();
        let mut err : i32 = 0;
        let expression_rosie_string = RosieString::from_str(expression);

        let result_code = unsafe { rosie_import_expression_deps(self.ptr(), &expression_rosie_string, ptr::null_mut(), &mut err, &mut message_buf) };

        if let Some(result_message) = messages {
            result_message.0.manual_drop(); //We're overwriting the string that was there
            result_message.0 = message_buf;
        } else {
            message_buf.manual_drop();
        }

        if result_code == 0 {
            if err == 0 {
                Ok(())
            } else {
                Err(RosieError::from(err)) //NOTE: we count on the Lua function to return the numeric value for either RosieError::ExpressionError or RosieError::PackageError
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
    /// # Example
    /// ```
    /// # use rosie::*;
    /// # let mut engine = engine::RosieEngine::new(None).unwrap();
    /// let pkg_name = engine.load_pkg_from_str("package two_digit_year\n\nyear = {[012][0-9]}", None).unwrap();
    /// assert_eq!(pkg_name.as_str(), "two_digit_year");
    /// ```
    /// 
    //INTERNAL NOTE: The call performs internal mutation on the engine, but it's safe because the mutated components can't
    // be referenced. See note on `RosieEngine::compile()`
    pub fn load_pkg_from_str(&self, rpl_text : &str, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {
        
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
    //INTERNAL NOTE: The call performs internal mutation on the engine, but it's safe because the mutated components can't
    // be referenced. See note on `RosieEngine::compile()`
    pub fn load_pkg_from_file<P: AsRef<Path>>(&self, file_name : P, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {

        //WARNING: Different OSs use different encodings for file paths.  Also there is no guarantee that file system paths
        // will be valid unicode (as Rust's str & String require).  There is a chance this will fail on some OSs.
        let file_name_rosie_string = RosieString::from_str(file_name.as_ref().to_str().unwrap());
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
    /// This method searches all directories that are part of the engine's `lib_path` (set using [lib_paths](RosieEngine::lib_paths)),
    /// searching for files named '`pkg_name.rpl`'.  When it finds the relevant `.rpl` file, the file is loaded and parsed,
    /// and the package name from the package's `package` declaration is returned.  It is a best practice for the filename to match the
    /// `package` declaration, but it is not enforced or required.
    /// 
    /// # Examples
    /// Without an alias:
    /// ```
    /// # use rosie::*;
    /// let mut engine = engine::RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", None, None);
    /// let date_pat = engine.compile("date.any", None).unwrap();
    /// ```
    /// With an alias:
    /// ```
    /// # use rosie::*;
    /// let mut engine = engine::RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", Some("special_date"), None);
    /// let date_pat = engine.compile("special_date.any", None).unwrap();
    /// ```
    /// 
    //INTERNAL NOTE: The call performs internal mutation on the engine, but it's safe because the mutated components can't
    // be referenced. See note on `RosieEngine::compile()`
    pub fn import_pkg(&self, pkg_name : &str, alias : Option<&str>, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {

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
    fn ptr(&self) -> EnginePtr;
    fn clone_private(&self) -> Self;
    fn match_pattern<'input>(&self, pattern_id : i32, start : usize, input : &'input [u8]) -> Result<MatchResult<'input>, RosieError>;
    fn match_pattern_raw<'engine>(&'engine self, pattern_id : i32, start : usize, input : &[u8], encoder : &MatchEncoder) -> Result<RawMatchResult<'engine>, RosieError>;
    fn trace_pattern(&self, pattern_id : i32, start : usize, input : &str, format : TraceFormat, trace : &mut RosieMessage) -> Result<bool, RosieError>;
}

impl PrivateRosieEngine for RosieEngine {
    // Private convenience to get the EnginePtr for the RosieEngine
    fn ptr(&self) -> EnginePtr {
        self.0.0
    }
    // Make a clone of the Engine.
    // RosieEngine is just an Rc pointer, so we can clone it to our heart's content, but externally, we don't want
    // users treating RosieEngine as Clone because it breaks a conceptual model.  For example, if a user cloned an
    // engine and changed a config parameter on a clone, it would be confusing when the setting also changed on the
    // original engine.
    fn clone_private(&self) -> Self {
        Self(self.0.clone())
    }

    // Returns a MatchResult, which deserializes the data from the RawMatchResult, so there is no pointer into the
    // engine after the call is complete.  However, the MatchResult contains references into the input string.
    fn match_pattern<'input>(&self, pattern_id : i32, start : usize, input : &'input [u8]) -> Result<MatchResult<'input>, RosieError> {
        
        let raw_match_result = self.match_pattern_raw(pattern_id, start, input, &MatchEncoder::Byte)?;
                
        if raw_match_result.did_match() {
            Ok(MatchResult::from_byte_match_result(input, raw_match_result))
        } else {
            Ok(MatchResult::new_no_match())
        }
    }

    // Returns a RawMatchResult, which contains a pointer into the engine that is accociated with the specific pattern_id
    fn match_pattern_raw<'engine>(&'engine self, pattern_id : i32, start : usize, input : &[u8], encoder : &MatchEncoder) -> Result<RawMatchResult<'engine>, RosieError> {

        if start < 1 || start > input.len() {
            return Err(RosieError::ArgError);
        }

        let input_rosie_string = RosieString::from_bytes(input);
        let mut match_result = RawMatchResult::empty();

        //Calling the rosie_match2 API, so we get our own dedicated results buffer for each pattern
        let result_code = unsafe{ rosie_match2(self.ptr(), pattern_id, encoder.as_bytes().as_ptr(), &input_rosie_string, u32::try_from(start).unwrap(), u32::try_from(input_rosie_string.len()+1).unwrap(), &mut match_result, 0) };

        if result_code == 0 {
            Ok(match_result)
        } else {
            Err(RosieError::from(result_code))
        }
    }

    // Executes the rosie_trace function.  All results are self-contained.
    fn trace_pattern(&self, pattern_id : i32, start : usize, input : &str, format : TraceFormat, trace : &mut RosieMessage) -> Result<bool, RosieError> {

        if start < 1 || start > input.len() {
            return Err(RosieError::ArgError);
        }
        
        let input_rosie_string = RosieString::from_str(input);
        let mut matched : i32 = -1;

        trace.0.manual_drop(); //We'll be overwriting whatever string was already there

        //NOTE: valid trace_style arguments are: "json\0", "full\0", and "condensed\0"
        let result_code = unsafe { rosie_trace(self.ptr(), pattern_id, i32::try_from(start).unwrap(), format.as_bytes().as_ptr(), &input_rosie_string, &mut matched, &mut trace.0) };

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

}
