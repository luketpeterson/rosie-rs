
//use std::ffi::CString;
use std::ptr;
use std::slice;
use std::str;
use std::mem::{transmute};
// use std::ffi::CStr;
// use std::borrow::Cow;
//use std::alloc::{dealloc, Layout};

extern crate libc;
use libc::{size_t, c_void};


//---Discussion about RosieStrings---
//RosieStrings appear to come in both an owned and borrowed flavor.  The data structures are identical, but the usage
//dictates who is responsible for deallocating the memory.  As a result, we have two separate structs to represent each
//type, RosieStringBorrowed and RosieStringOwned.  We have a third struct called RosieStringInternal to implement all
//of the common accessors and convenience functions.  Because the memory layout is identical, we can transmute between
//the flavors freely.  Publicly, we then expose an enum wrapping both types to make it transparent to the API user
//what kind of string they are dealing with.

#[derive(Debug)]
#[repr(C)]
pub struct RosieStringOwned {
    len: u32,
    ptr: *const u8
}

impl RosieStringOwned {
    fn empty() -> Self {
        Self {
            len: 0,
            ptr: ptr::null()
        }
    }
    pub fn owned_from_str(s: &str) -> Self {
        unsafe { rosie_new_string(s.as_ptr(), s.len()) }
    }
    fn to_generic(&self) -> &RosieStringGeneric {
        unsafe { transmute(self) }
    }
}

//If it's the owned variant, we are responsible for freeing any string buffers, even if librosie allocated them
impl Drop for RosieStringOwned {
    fn drop(&mut self) {
        if self.ptr != ptr::null() {
            let self_copy = RosieStringOwned { len : self.len, ptr : self.ptr };
            unsafe { rosie_free_string(self_copy); }
        }
    }
}


//BORIS DELETE THESE COMMENTS
//Identical to a RosieString, except that we don't free it when it's dropped
//Currently it's used for match results' data buffer, because the engine owns that
//TODO: Expose a unified type that allows a RosieString to be created from borrowed data as well.
//  That will entail wrapping the RosieString in an outer struct to track whether it's owned or borrowed.
//  Steps: 1. Create a RosieStringInternal that is a generic interface where the implementation lives
//  2. Change the owned variant into an explicit object separate from the generic
//  3. Create a public enum that is exported to all public APIs
#[derive(Debug)]
#[repr(C)]
struct RosieStringBorrowed {
    len: u32,
    ptr: *const u8
}

impl RosieStringBorrowed {
    fn empty() -> Self {
        Self {
            len: 0,
            ptr: ptr::null()
        }
    }
    fn to_generic(&self) -> &RosieStringGeneric {
        unsafe { transmute(self) }
    }
}

#[derive(Debug)]
#[repr(C)]
struct RosieStringGeneric {
    len: u32,
    ptr: *const u8
}

impl RosieStringGeneric {
    pub fn as_str(&self) -> &str {
        if self.ptr != ptr::null() {
            let string_slice = unsafe{ slice::from_raw_parts(self.ptr, self.len as usize) };
            str::from_utf8(string_slice).unwrap()
        } else {
            ""
        }
    }
    pub fn len(&self) -> usize {
        self.len as usize
    }
}

//Struct for passing text buffers to and from librosie
#[derive(Debug)]
pub enum RosieString {
    Owned(RosieStringOwned),
    Borrowed(RosieStringBorrowed)
}

//QUESTION FOR A ROSIE EXPERT: How useful are the status messages in the success case?
//It feels like a cleaner interface if we could get rid of the messages optional parameter, and pass back the messages
//  with the error code.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum RosieError {
    Success = 0,
    MiscErr = -1,
    OutOfMemory = -2,
    SysCallFailed = -3,
    EngineCallFailed = -4,
}

impl RosieError {
    pub fn from(code: i32) -> Self {
        match code {
            0 => RosieError::Success,
            -2 => RosieError::OutOfMemory,
            -3 => RosieError::SysCallFailed,
            -4 => RosieError::EngineCallFailed,
            _ => RosieError::MiscErr
        }
    }
}

#[repr(C)]
pub struct RosieEngine(*mut c_void);

//Give librosie a chance to clean up the engine
impl Drop for RosieEngine {
    fn drop(&mut self) {
        let self_copy = RosieEngine(self.0);
        unsafe{ rosie_finalize(self_copy); }
    }
}

impl RosieEngine {
    pub fn new(messages : Option<&mut RosieString>) -> Result<Self, RosieError> {
        
        let mut message_buf = RosieStringOwned::empty().to_generic();
        // let result_messages = match messages {
        //     Some(result_messages) => result_messages,
        //     None => &mut message_buf
        // };

        //GOATGOATHERE!!!!!! The solution is that I need to pass back a an owned, regardless of what I got passed in, if something was passed in at all
        //NOOOOOOOO!!!!!! Better solution:
        //  RosieStrings are internal and non-public
        //  "RosieMessage"s are public, and freed when dropped.  They are just a public wrapper around RosieString
        //  All incoming text buffers can come in as regular Rust strings

        let rosie_engine = unsafe { rosie_new(result_messages) };

        if rosie_engine.0 as *const _ != ptr::null() {
            Ok(rosie_engine)
        } else {
            Err(RosieError::MiscErr)
        }
    }
    pub fn compile(&mut self, expression : &RosieString, messages : Option<&mut RosieString>) -> Result<PatternID, RosieError> {

        let mut pat_idx : i32 = 0;
        let mut message_buf = RosieString::empty();
        let result_messages = match messages {
            Some(result_messages) => result_messages,
            None => &mut message_buf
        };

        let self_copy = RosieEngine(self.0);
        let result_code = unsafe { rosie_compile(self_copy, expression, &mut pat_idx, result_messages) };

        //QUESTION FOR A ROSIE EXPERT.  There appears to a bug in the implementation of rosie_compile.
        //*pat is set to 0 before pat is checked against NULL, meaning that if it were null the code already would have crashed
        //  before the check.  So the check is pointless.
        //QUESTION FOR A ROSIE EXPERT.  Why is it that an invalid pattern syntax will result in a Success result code, even if
        //  the returned pattern index is 0?  I don't want invalid PatternIDs to be possible in Rust, therefore, I'm also
        //  checking the pattern index against 0.  Am I misunderstanding the librosie interface?
        if result_code == 0 && pat_idx > 0 {
            Ok(PatternID(pat_idx))
        } else {
            Err(RosieError::from(result_code))
        }
    }
    pub fn free_pattern(&mut self, pattern_id : PatternID) -> Result<(), RosieError> {
        let self_copy = RosieEngine(self.0);
        let result_code = unsafe { rosie_free_rplx(self_copy, pattern_id.0) };

        if result_code == 0 {
            Ok(())
        } else {
            Err(RosieError::from(result_code))
        }
    }
    pub fn match_pattern(&mut self, pattern_id : PatternID, start : usize, input : &RosieString, match_result : &mut RosieMatchResult) -> Result<(), RosieError> {
        
        //TODO: Better encoder integration with Rust
        //DISCUSSION: Temporarily we are using the JSON encoder for the results.  However, there are certainly better options.
        //For most languages, the sensible thing is to go straight into native language types.  Unfortunately Rust's typing
        //system is too rigid to do this easily.
        //Option 1. Serde marries Rust's type system with an abstract deserialization process in the best manner possible.
        //  Rosie could be integrated as a Serde deserialization format.  I am against this approach, however, because A tight
        //  coupling between the rust strctures and the rosie patterns would be required.  This would be very hard to use and
        //  even harder to debug.  Also, it defeats some of the point of the flexibility of Rosie.
        //Option 2. A flexible value type, along the lines of serde_json::value::Value.  This is probably the most expedient
        //  stop-gap, but ultimately working with these is tedious as there is a lot of type-checking code needed all over the
        //  place.
        //Option 3. A high-level result-description mechanism.  This is a more ambitious proposal that may require buy-in from
        //  the core Rosie team.  But I think it would provide the most elegant and useful integration possibilities.
        
        let self_copy = RosieEngine(self.0);
        let result_code = unsafe{ rosie_match(self_copy, pattern_id.0, start as i32, "json\0".as_ptr(), input, match_result) }; 

        if result_code == 0 {
            Ok(())
        } else {
            Err(RosieError::from(result_code))
        }
    }
    pub fn trace_pattern(&mut self, pattern_id : PatternID, start : usize, input : &RosieString, trace : &mut RosieString) -> Result<bool, RosieError> {

        let mut matched : i32 = -1;
        let self_copy = RosieEngine(self.0);
        //NOTE: valid trace_style arguments are: "json\0", "full\0", and "condensed\0"
        let result_code = unsafe { rosie_trace(self_copy, pattern_id.0, start as i32, "condensed\0".as_ptr(), input, &mut matched, trace) };

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

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct PatternID(i32);

#[repr(C)]
#[derive(Debug)]
pub struct RosieMatchResult {
    data: RosieStringBorrowed,
    leftover: i32,
    abend: i32,
    ttotal: i32,
    tmatch: i32
}

impl RosieMatchResult {
    pub fn empty() -> Self {
        Self {
            data: RosieStringBorrowed::empty(),
            leftover: 0,
            abend: 0,
            ttotal: 0,
            tmatch: 0
        }
    }
}



//Interfaces to the raw librosie functions
//NOTE: Not all interfaces are imported by the Rust driver
extern "C" {
    fn rosie_new_string(msg : *const u8, len : size_t) -> RosieStringOwned; // str rosie_new_string(byte_ptr msg, size_t len);
    // str *rosie_new_string_ptr(byte_ptr msg, size_t len);
    // str *rosie_string_ptr_from(byte_ptr msg, size_t len);
    // str rosie_string_from(byte_ptr msg, size_t len);
    fn rosie_free_string(s : RosieStringOwned); // void rosie_free_string(str s);
    // void rosie_free_string_ptr(str *s);
    
    fn rosie_new(messages : *mut RosieString) -> RosieEngine; // Engine *rosie_new(str *messages);
    fn rosie_finalize(engine : RosieEngine); // void rosie_finalize(Engine *e);
    // int rosie_libpath(Engine *e, str *newpath);
    // int rosie_alloc_limit(Engine *e, int *newlimit, int *usage);
    // int rosie_config(Engine *e, str *retvals);
    fn rosie_compile(engine : RosieEngine, expression : *const RosieString, pat : *mut i32, messages : *mut RosieString) -> i32; // int rosie_compile(Engine *e, str *expression, int *pat, str *messages);
    fn rosie_free_rplx(engine : RosieEngine, pat : i32) -> i32; // int rosie_free_rplx(Engine *e, int pat);
    fn rosie_match(engine : RosieEngine, pat : i32, start : i32, encoder : *const u8, input : *const RosieString, match_result : *mut RosieMatchResult) -> i32; // int rosie_match(Engine *e, int pat, int start, char *encoder, str *input, match *match);
    // int rosie_matchfile(Engine *e, int pat, char *encoder, int wholefileflag,
    //            char *infilename, char *outfilename, char *errfilename,
    //            int *cin, int *cout, int *cerr,
    //            str *err);
    fn rosie_trace(engine : RosieEngine, pat : i32, start : i32, trace_style : *const u8, input : *const RosieString, matched : &mut i32, trace : *mut RosieString) -> i32; // int rosie_trace(Engine *e, int pat, int start, char *trace_style, str *input, int *matched, str *trace);
    // int rosie_load(Engine *e, int *ok, str *src, str *pkgname, str *messages);
    // int rosie_loadfile(Engine *e, int *ok, str *fn, str *pkgname, str *messages);
    // int rosie_import(Engine *e, int *ok, str *pkgname, str *as, str *actual_pkgname, str *messages);
    // int rosie_read_rcfile(Engine *e, str *filename, int *file_exists, str *options, str *messages);
    // int rosie_execute_rcfile(Engine *e, str *filename, int *file_exists, int *no_errors, str *messages);

    // int rosie_expression_refs(Engine *e, str *input, str *refs, str *messages);
    // int rosie_block_refs(Engine *e, str *input, str *refs, str *messages);
    // int rosie_expression_deps(Engine *e, str *input, str *deps, str *messages);
    // int rosie_block_deps(Engine *e, str *input, str *deps, str *messages);
    // int rosie_parse_expression(Engine *e, str *input, str *parsetree, str *messages);
    // int rosie_parse_block(Engine *e, str *input, str *parsetree, str *messages);

    

}

#[test]
fn rosie_string() {
    let hello_str = "hello";
    let rosie_string = RosieString::from_str(hello_str);
    assert_eq!(rosie_string.len(), hello_str.len());
    assert_eq!(rosie_string.as_str(), hello_str);
}

#[test]
fn rosie_engine() {

    //Create the engine and check that it was sucessful
    let mut engine = RosieEngine::new(None).unwrap();

    //Compile a valid rpl pattern, and confirm there is no error
    let pat_idx = engine.compile(&RosieString::from_str("{[012][0-9]}"), None).unwrap();

    //Make sure we can sucessfully free the pattern
    assert!(engine.free_pattern(pat_idx).is_ok());
    
    //Try to compile an invalid pattern (syntax error), and check the error and error message
    let mut message = RosieString::empty();
    let compile_result = engine.compile(&RosieString::from_str("year = bogus"), Some(&mut message));
    assert!(compile_result.is_err());
    assert!(message.len() > 0);
    //println!("{}", message.as_str());

    //Recompile a pattern expression and match it against a matching input
    let pat_idx = engine.compile(&RosieString::from_str("{[012][0-9]}"), None).unwrap();
    let mut match_result = RosieMatchResult::empty();
    //QUESTION FOR A ROSIE EXPERT: The start index seems to be 1-based.  why?  Passing 0 just seems to mess everything up.
    //  For example, it causes "rosie_match" not to match, while "rosie_trace" does match, but claims to match one
    //  character more than the pattern really matched
    //QUESTION FOR A ROSIE EXPERT: The start index seems to be 1-based.  why?  Passing 0 just seems to mess everything up
    assert!(engine.match_pattern(pat_idx, 1, &RosieString::from_str("25"), &mut match_result).is_ok());
    
    println!("zook {:?}", match_result);
    println!("result {}", match_result.data.to_generic().as_str());


    let mut trace = RosieString::empty();
    assert!(engine.trace_pattern(pat_idx, 1, &RosieString::from_str("25"), &mut trace).is_ok());

    println!("zuuk {}", trace.as_str());


        // let mut input_string = RosieString::empty();
        // let mut match_result = RosieMatchResult::empty();

        // //let my_ptr : *const u32 = transmute(rosie_engine.0);
        // //println!("BORK {}, {}, {:?}", pat_idx, messages.as_str(), my_ptr);

        println!("BORK {:?}", pat_idx);
        
        // //let result = rosie_match(rosie_engine, 0, 0, "\0".as_ptr(), &mut input_string, &mut match_result);

        // println!("BONK {:?}", match_result.data.ptr);



    

}


