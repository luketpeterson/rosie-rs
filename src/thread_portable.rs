
use std::path::{PathBuf, Path};
use std::sync::{Arc, Mutex};

use crate::rosie_sys::{rosie_free_rplx};
use crate::{RawEngine, RosieMessage, RosieError, RawMatchResult, MatchEncoder, MatchOutput, TraceFormat};

/// The Rust object representing a Rosie engine that can safely be accessed by multiple threads
pub struct PortableEngine(pub(crate) Arc<Mutex<RawEngine>>);

impl PortableEngine {
    /// See [RosieEngine::new](crate::RosieEngine::new)
    pub fn new(messages : Option<&mut RosieMessage>) -> Result<Self, RosieError> {
        Ok(PortableEngine(Arc::new(Mutex::new(RawEngine::new(messages)?))))
    }
    /// See [RosieEngine::lib_paths](crate::RosieEngine::lib_paths)
    pub fn lib_paths(&self) -> Result<Vec<PathBuf>, RosieError> {
        self.0.lock().unwrap().lib_paths()
    }
    /// See [RosieEngine::set_lib_paths](crate::RosieEngine::set_lib_paths)
    pub fn set_lib_paths<P: AsRef<Path>>(&mut self, new_paths : &[P]) -> Result<(), RosieError> {
        self.0.lock().unwrap().set_lib_paths(new_paths)
    }
    /// See [RosieEngine::mem_alloc_limit](crate::RosieEngine::mem_alloc_limit)
    pub fn mem_alloc_limit(&self) -> Result<usize, RosieError> {
        self.0.lock().unwrap().mem_alloc_limit()
    }
    /// See [RosieEngine::set_mem_alloc_limit](crate::RosieEngine::set_mem_alloc_limit)
    pub fn set_mem_alloc_limit(&mut self, new_limit : usize) -> Result<(), RosieError> {
        self.0.lock().unwrap().set_mem_alloc_limit(new_limit)
    }
    /// See [RosieEngine::mem_usage](crate::RosieEngine::mem_usage)
    pub fn mem_usage(&self) -> Result<usize, RosieError> {
        self.0.lock().unwrap().mem_usage()
    }
    /// See [RosieEngine::config_as_json](crate::RosieEngine::config_as_json)
    pub fn config_as_json(&self) -> Result<RosieMessage, RosieError> {
        self.0.lock().unwrap().config_as_json()
    }
    /// See [RosieEngine::compile](crate::RosieEngine::compile)
    pub fn compile(&self, expression : &str, messages : Option<&mut RosieMessage>) -> Result<PortablePattern, RosieError> {

        let pat_idx = self.0.lock().unwrap().compile(expression, messages)?;

        //NOTE: This is the only place a PortableEngine's Arc pointer gets cloned.  See the note around the
        // definition of RosieEngine, because PortableEngine uses the same strategy
        Ok(PortablePattern{
            engine : PortableEngine(self.0.clone()),
            id : pat_idx    
        })
    }
    /// See [RosieEngine::import_expression_deps](crate::RosieEngine::import_expression_deps)
    pub fn import_expression_deps(&self, expression : &str, messages : Option<&mut RosieMessage>) -> Result<(), RosieError> {
        self.0.lock().unwrap().import_expression_deps(expression, messages)
    }
    /// See [RosieEngine::load_pkg_from_str](crate::RosieEngine::load_pkg_from_str)
    pub fn load_pkg_from_str(&self, rpl_text : &str, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {
        self.0.lock().unwrap().load_pkg_from_str(rpl_text, messages)
    }
    /// See [RosieEngine::load_pkg_from_file](crate::RosieEngine::load_pkg_from_file)
    pub fn load_pkg_from_file<P: AsRef<Path>>(&self, file_name : P, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {
        self.0.lock().unwrap().load_pkg_from_file(file_name, messages)
    }
    /// See [RosieEngine::import_pkg](crate::RosieEngine::import_pkg)
    pub fn import_pkg(&self, pkg_name : &str, alias : Option<&str>, messages : Option<&mut RosieMessage>) -> Result<RosieMessage, RosieError> {
        self.0.lock().unwrap().import_pkg(pkg_name, alias, messages)
    }
}

/// A version of [Pattern](crate::Pattern) that can be shared between threads
pub struct PortablePattern {
    pub(crate) engine: PortableEngine,
    pub(crate) id : i32
}

impl Drop for PortablePattern {
    fn drop(&mut self) {
        unsafe { rosie_free_rplx(self.engine.0.lock().unwrap().0, self.id) };
    }
}

impl PortablePattern {
    /// See [Pattern::match_bytes](crate::Pattern::match_bytes)
    pub fn match_bytes<'input, T>(&self, input : &'input [u8]) -> Result<T, RosieError> 
    where T : MatchOutput<'input> {
        //Call the return-type-specific match call
        T::match_bytes_portable(self, input)
    }
    
    /// See [Pattern::match_str](crate::Pattern::match_str)
    pub fn match_str<'input, T>(&self, input : &'input str) -> Result<T, RosieError> 
    where T : MatchOutput<'input> {
        self.match_bytes(input.as_bytes())
    }

    /// See [Pattern::raw_match](crate::Pattern::raw_match)
    pub fn raw_match(&self, start : usize, input : &[u8], encoder : &MatchEncoder) -> Result<OwnedRawMatchResult, RosieError> {

        let guard = self.engine.0.lock().unwrap();
        let raw_match_result = guard.match_pattern_raw(self.id, start, input, encoder)?;
        Ok(OwnedRawMatchResult::from_raw_match_result(&raw_match_result))
    }
    /// See [Pattern::trace](crate::Pattern::trace)
    pub fn trace(&self, start : usize, input : &str, format : TraceFormat, trace : &mut RosieMessage) -> Result<bool, RosieError> {
        self.engine.0.lock().unwrap().trace_pattern(self.id, start, input, format, trace)
    }
}

/// An owned equivalent to [RawMatchResult](crate::RawMatchResult) that doesn't reference any memory
/// inside the Rosie engine
pub struct OwnedRawMatchResult {
    did_match: bool,
    data: RosieMessage,
    ttotal: usize,
    tmatch: usize
}

impl OwnedRawMatchResult {
    fn from_raw_match_result(raw_match_result: &RawMatchResult<'_>) -> Self {
        Self{
            did_match: raw_match_result.did_match(),
            data: RosieMessage::from_bytes(raw_match_result.as_bytes()),
            ttotal: raw_match_result.time_elapsed_total(),
            tmatch: raw_match_result.time_elapsed_matching(),
        }
    }
    /// Returns `true` if the pattern was matched in the input, otherwise returns `false`.
    pub fn did_match(&self) -> bool {
        self.did_match
    }
    /// Returns the raw buffer, outputted by the encoder during the match operation
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }
    /// Returns the match buffer, interpreted as a UTF-8 string
    pub fn as_str(&self) -> &str {
        self.data.as_str()
    }
    /// Returns the total time, in microseconds, elapsed during the match call, inside librosie.
    pub fn time_elapsed_total(&self) -> usize {
        self.ttotal
    }
    /// Returns the time, in microseconds, elapsed matching the pattern against the input.
    /// 
    /// This value excludes time spend encoding the results
    pub fn time_elapsed_matching(&self) -> usize {
        self.tmatch
    }
}
