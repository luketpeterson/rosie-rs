
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
    rosie_expression_deps,
};
use crate::sys_shadow::{*};
use crate::{RosieMessage, Pattern, MatchResult, librosie_init};

//A wrapper around an EnginePtr so we can implement Drop
//NOTE: Only pub within this crate
pub struct RawEngine<'a>(EnginePtr<'a>);

//Give librosie a chance to clean up the engine
impl Drop for RawEngine<'_> {
    fn drop(&mut self) {
        unsafe{ rosie_finalize(self.0); }
    }
}

//GOAT, A RosieEngine shouldn't have a lifetime.  A pattern does need a lifetime because it borrows a RosieEngine
//GOAT, Audit whether each call should take a mutable engine or not.  Document why the calls that don't take a mutable engine are ok

/// The Rust object representing a Rosie engine.  Used when direct access to rosie engines is desired.
/// 
/// **NOTE**: RosieEngines are not internally thread-safe and don't implemnt [Sync] or [Send].  You may create more than one RosieEngine in
/// order to use multiple threads.  Also there is a thread-local `default_engine` accessible through [Rosie::with_default_engine].
/// 
// TODO: This is a 3-level indirection because the RawEngine itself is a ptr.  Maybe this can be improved
// if this turns out to be a bottleneck.);
pub struct RosieEngine<'a>(Rc<RawEngine<'a>>);

impl <'a>RosieEngine<'a> {
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
    pub fn lib_path(&self) -> Result<&Path, RosieError> {

        let mut path_rosie_string = RosieString::empty();
        
        let result_code = unsafe { rosie_libpath(self.ptr(), &mut path_rosie_string) };

        if result_code == 0 {
            Ok(Path::new(path_rosie_string.into_str()))
        } else {
            Err(RosieError::from(result_code))
        }
    }
    /// Sets the directory to use when loading packages from the standard pattern library.
    /// 
    /// This will affect the behavior of [import_pkg](RosieEngine::import_pkg), as well as any other operations that load rpl code using the `import` directive.
    pub fn set_lib_path<P: AsRef<Path>>(&mut self, new_path : P) -> Result<(), RosieError> {

        let mut path_rosie_string = RosieString::from_str(new_path.as_ref().to_str().unwrap());

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
    /// Compiles the specified expression into a `Pattern` hosted by the `Engine`.
    /// 
    /// This is a lower-level interface than [Pattern::compile].  Expression dependencies must be manually imported using
    /// any of [load_expression_deps](RosieEngine::load_expression_deps), [RosieEngine::load_pkg_from_str],
    /// [RosieEngine::load_pkg_from_file], or [RosieEngine::import_pkg].
    /// 
    /// # Examples
    /// ```
    /// # use rosie_rs::*;
    /// let mut engine = engine::RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", None, None);
    /// let date_pat = engine.compile("date.us_long", None).unwrap();
    /// ```
    /// 
    pub fn compile(&self, expression : &str, messages : Option<&mut RosieMessage>) -> Result<Pattern<'a>, RosieError> {

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
                Err(RosieError::PatternError)
            }
        } else {
            Err(RosieError::from(result_code))
        }
    }

    /// Parses an rpl expression and loads any dependencies 
    //TODO: It actually bugs me greatly that we need serde as a dependency in release mode, and even more so that we have
    // to go through JSON to get expression dependencies out of rosie.  Maybe this can be improved in the future, but 
    // realistically it's not a serious problem.
    pub fn load_expression_deps(&self, expression : &str, messages : Option<&mut RosieMessage>) -> Result<(), RosieError> {

        let mut deps_buf = RosieString::empty();
        let mut message_buf = RosieString::empty();
        let expression_rosie_string = RosieString::from_str(expression);

        //Parse the expression to extract any dependencies
        let result_code = unsafe { rosie_expression_deps(self.ptr(), &expression_rosie_string, &mut deps_buf, &mut message_buf) };

        let mut result_messages = messages;
        if let Some(result_messages) = &mut result_messages {
            result_messages.0.manual_drop(); //We're overwriting the string that was there
            result_messages.0 = message_buf;
        } else {
            message_buf.manual_drop();
        }

        //If we got the deps as a JSON string from librosie, get ready to parse it
        if result_code == 0 {

            //If there are no deps, we get back an empty string rather than an array
            if deps_buf.len() > 2 {
                let parsed_deps : Vec<&str> = serde_json::from_slice(deps_buf.as_bytes()).unwrap();
    
                //Loop over each dep and load it
                for dep in parsed_deps {

                    let mut temp_messages = RosieMessage::empty();
                    let result = self.import_pkg(dep, None, Some(&mut temp_messages));

                    if let Err(err) = result {
                        deps_buf.manual_drop();

                        if let Some(result_messages) = result_messages {
                            *result_messages = temp_messages;
                        }

                        return Err(err);
                    }
                }    
            }

            deps_buf.manual_drop();
            Ok(())
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
    pub fn load_pkg_from_file<P: AsRef<Path>>(&self, file_name : P, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {

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
    /// This function searches all directories that are part of the engine's `lib_path` (set using [lib_path](RosieEngine::lib_path)),
    /// searching for files named '`pkg_name.rpl`'.  When it finds the relevant `.rpl` file, the file is loaded and parsed,
    /// and the package name from the package's `package` declaration is returned.  It is a best practice for the filename to match the
    /// `package` declaration, but it is not enforced or required.
    /// 
    /// # Examples
    /// Without an alias:
    /// ```
    /// # use rosie_rs::*;
    /// let mut engine = engine::RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", None, None);
    /// let date_pat = engine.compile("date.any", None).unwrap();
    /// ```
    /// With an alias:
    /// ```
    /// # use rosie_rs::*;
    /// let mut engine = engine::RosieEngine::new(None).unwrap();
    /// engine.import_pkg("date", Some("special_date"), None);
    /// let date_pat = engine.compile("special_date.any", None).unwrap();
    /// ```
    /// 
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
    fn ptr(&self) -> EnginePtr<'_>;
    fn clone_private(&self) -> Self;
    fn match_pattern<'input>(&self, pattern_id : i32, start : usize, input : &'input str) -> Result<MatchResult<'input>, RosieError>;
    fn match_pattern_raw<'engine>(&'engine self, pattern_id : i32, start : usize, input : &str, encoder : &MatchEncoder) -> Result<RawMatchResult<'engine>, RosieError>;
    fn trace_pattern(&self, pattern_id : i32, start : usize, input : &str, format : TraceFormat, trace : &mut RosieMessage) -> Result<bool, RosieError>;
}

impl PrivateRosieEngine for RosieEngine<'_> {
    // Private convenience to get the EnginePtr for the RosieEngine
    fn ptr(&self) -> EnginePtr<'_> {
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
    fn match_pattern<'input>(&self, pattern_id : i32, start : usize, input : &'input str) -> Result<MatchResult<'input>, RosieError> {
        
        let raw_match_result = self.match_pattern_raw(pattern_id, start, input, &MatchEncoder::Byte)?;
                
        if raw_match_result.did_match() {
            Ok(MatchResult::from_byte_match_result(input, raw_match_result))
        } else {
            Ok(MatchResult::new_no_match())
        }
    }

    // Returns a RawMatchResult, which contains a pointer into the engine that is accociated with the specific pattern_id
    fn match_pattern_raw<'engine>(&'engine self, pattern_id : i32, start : usize, input : &str, encoder : &MatchEncoder) -> Result<RawMatchResult<'engine>, RosieError> {

        if start < 1 || start > input.len() {
            return Err(RosieError::ArgError);
        }

        let input_rosie_string = RosieString::from_str(input);
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
