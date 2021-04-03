
//use std::ffi::CString;
use std::marker::PhantomData;
use std::ptr;
use std::slice;
use std::str;
//use std::mem::{transmute};
// use std::ffi::CStr;
// use std::borrow::Cow;
//use std::alloc::{dealloc, Layout};

extern crate libc;
use libc::{size_t, c_void};


//---Discussion about RosieString (rstr in librosie)---
//Strings in librose can either be allocated by the librosie library or allocated by the client.  The buffer containing
//the actual bytes therefore must be freed or not freed depending on knowledge of where the string came from.  This
//makes a straightforward wrapper in Rust problematic.  It would be possible to expose a smart wrapper with knowledge
//about whether a buffer should be freed or not, but this adds extra complexity and overhead.  In fact I already wrote
//this and then decided against it after seeing how it looked and realizing there was very little need to expose
//librosie strings to Rust.
//
//Now, the RosieString struct is kept private, but we expose a specialized variant called RosieMessage.  A RosieMessage
//is a RosieString that was allocated by librosie, but where the client is responsible for freeing it
//
//Simply put, RosieString doesn't own its buffer, and it a glorified pointer.  RosieMessage does own its buffer, and
//frees it when dropped.  But the memory layout of both structures is identical.

#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct RosieString<'a> {
    len: u32,
    ptr: *const u8, //This pointer really has a lifetime of 'a, hence the phantom
    phantom: PhantomData<&'a u8>,
}

impl RosieString<'_> {
    fn empty() -> Self {
        Self {
            len: 0,
            ptr: ptr::null(),
            phantom: PhantomData
        }
    }
    fn from_str(s: &str) -> Self {
        unsafe { rosie_string_from(s.as_ptr(), s.len()) }
    }
    fn as_str(&self) -> &str {
        if self.ptr != ptr::null() {
            let string_slice = unsafe{ slice::from_raw_parts(self.ptr, self.len as usize) };
            str::from_utf8(string_slice).unwrap()
        } else {
            ""
        }
    }
    fn len(&self) -> usize {
        self.len as usize
    }
}

#[derive(Debug)]
pub struct RosieMessage(RosieString<'static>);

//If it's the owned variant, we are responsible for freeing any string buffers, even if librosie allocated them
impl Drop for RosieMessage {
    fn drop(&mut self) {
        if self.0.ptr != ptr::null() {
            unsafe { rosie_free_string(self.0); }
        }
    }
}

impl RosieMessage {
    pub fn empty() -> Self {
        Self(RosieString::empty())
    }
    pub fn from_str(s: &str) -> Self {
        let rosie_string = unsafe { rosie_new_string(s.as_ptr(), s.len()) };
        Self(rosie_string)
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
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
pub struct RosieEngine<'a> {
    e: *mut c_void, //This pointer really has a lifetime of 'a, hence the phantom
    phantom: PhantomData<&'a u8>,
}

//Give librosie a chance to clean up the engine
impl Drop for RosieEngine<'_> {
    fn drop(&mut self) {
        unsafe{ rosie_finalize(self.copy_self()); }
    }
}

impl RosieEngine<'_> {
    //Internal function that should compile to a noop.  Just here to prepare the arg to call into C
    fn copy_self(&mut self) -> Self {
        RosieEngine{e: self.e, phantom : self.phantom}
    }
    pub fn new(messages : Option<&mut RosieMessage>) -> Result<Self, RosieError> {
        
        let mut message_buf = RosieString::empty();

        let rosie_engine = unsafe { rosie_new(&mut message_buf) };

        if let Some(result_message) = messages {
            result_message.0 = message_buf;
        }

        if rosie_engine.e as *const _ != ptr::null() {
            Ok(rosie_engine)
        } else {
            Err(RosieError::MiscErr)
        }
    }
    pub fn compile(&mut self, expression : &str, messages : Option<&mut RosieMessage>) -> Result<PatternID, RosieError> {

        let mut pat_idx : i32 = 0;
        let mut message_buf = RosieString::empty();

        //QUESTION FOR A ROSIE EXPERT.  Is it safe to assume that the engine will fully ingest the expression, and it is
        //safe to deallocate the expression string when this function returns?  I am assuming yes, but if not, this code
        //must change.
        let expression_rosie_string = RosieString::from_str(expression);

        let result_code = unsafe { rosie_compile(self.copy_self(), &expression_rosie_string, &mut pat_idx, &mut message_buf) };

        if let Some(result_message) = messages {
            result_message.0 = message_buf;
        }
        
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
        let result_code = unsafe { rosie_free_rplx(self.copy_self(), pattern_id.0) };

        if result_code == 0 {
            Ok(())
        } else {
            Err(RosieError::from(result_code))
        }
    }

    //QUESTION FOR A ROSIE EXPERT.  I assume that the string inside the match results points to memory managed by the input string.
    //Is this right?  Therefore, the engine could be safely deallocated and the match buffer would still be fine, but if the input
    //string's buffer were deallocated then the match result would point to freed memory?  Is this right, or is the memory actuall
    //owned by the engine, and I need to make sure the engine isn't deallocated before the match result?
    pub fn match_pattern<'input>(&mut self, pattern_id : PatternID, start : usize, input : &'input str) -> Result<RosieMatchResult<'input>, RosieError> {
        
        //QUESTION FOR A ROSIE EXPERT.  Is it safe to assume that the engine will fully ingest the input, and it is
        //safe to deallocate the expression string after this function returns?  I am assuming yes, but if not, this code
        //must change.
        let input_rosie_string = RosieString::from_str(input);

        let mut match_result = RosieMatchResult::empty();

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
        
        let result_code = unsafe{ rosie_match(self.copy_self(), pattern_id.0, start as i32, "json\0".as_ptr(), &input_rosie_string, &mut match_result) }; 

        //QUESTION FOR A ROSIE EXPERT.  the match_result.ttotal and match_result.tmatch fields seem to often get non-deterministic values
        //that vary from one run to the next.  Although the numbers are always within reasonable ranges.  Nonetheless, This scares me.
        //It feels like uninitialized memory or something might be influencing the run.
        
        if result_code == 0 {
            Ok(match_result)
        } else {
            Err(RosieError::from(result_code))
        }
    }
    pub fn trace_pattern(&mut self, pattern_id : PatternID, start : usize, input : &str, trace : &mut RosieMessage) -> Result<bool, RosieError> {

        //QUESTION FOR A ROSIE EXPERT.  Is it safe to assume that the engine will fully ingest the input, and it is
        //safe to deallocate the expression string after this function returns?  I am assuming yes, but if not, this code
        //must change.
        let input_rosie_string = RosieString::from_str(input);

        let mut matched : i32 = -1;

        //NOTE: valid trace_style arguments are: "json\0", "full\0", and "condensed\0"
        let result_code = unsafe { rosie_trace(self.copy_self(), pattern_id.0, start as i32, "condensed\0".as_ptr(), &input_rosie_string, &mut matched, &mut trace.0) };

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
pub struct RosieMatchResult<'a> {
    data: RosieString<'a>,
    leftover: i32,
    abend: i32,
    ttotal: i32,
    tmatch: i32
}

impl RosieMatchResult<'_> {
    pub fn empty() -> Self {
        Self {
            data: RosieString::empty(),
            leftover: 0,
            abend: 0,
            ttotal: 0,
            tmatch: 0
        }
    }
}



//Interfaces to the raw librosie functions
//NOTE: Not all interfaces are imported by the Rust driver
//NOTE: The 'static lifetime in the returned values is a LIE! The calling code needs to assign the lifetimes appropriately
extern "C" {
    fn rosie_new_string(msg : *const u8, len : size_t) -> RosieString<'static>; // str rosie_new_string(byte_ptr msg, size_t len);
    // str *rosie_new_string_ptr(byte_ptr msg, size_t len);
    // str *rosie_string_ptr_from(byte_ptr msg, size_t len);
    fn rosie_string_from(msg : *const u8, len : size_t) -> RosieString<'static>; // str rosie_string_from(byte_ptr msg, size_t len);
    fn rosie_free_string(s : RosieString); // void rosie_free_string(str s);
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
    let pat_idx = engine.compile("{[012][0-9]}", None).unwrap();

    //Make sure we can sucessfully free the pattern
    assert!(engine.free_pattern(pat_idx).is_ok());
    
    //Try to compile an invalid pattern (syntax error), and check the error and error message
    let mut message = RosieMessage::empty();
    let compile_result = engine.compile("year = bogus", Some(&mut message));
    assert!(compile_result.is_err());
    assert!(message.len() > 0);
    //println!("{}", message.as_str());

    //Recompile a pattern expression and match it against a matching input
    let pat_idx = engine.compile("{[012][0-9]}", None).unwrap();
    //QUESTION FOR A ROSIE EXPERT: The start index seems to be 1-based.  why?  Passing 0 just seems to mess everything up.
    //  For example, it causes "rosie_match" not to match, while "rosie_trace" does match, but claims to match one
    //  character more than the pattern really matched
    let match_result = engine.match_pattern(pat_idx, 1, "21").unwrap();

    println!("zook {:?}", match_result);
    println!("result {}", match_result.data.as_str());


    let mut trace = RosieMessage::empty();
    assert!(engine.trace_pattern(pat_idx, 1, "21", &mut trace).is_ok());

    println!("zuuk {}", trace.as_str());


        // let mut input_string = RosieString::empty();
        // let mut match_result = RosieMatchResult::empty();

        // //let my_ptr : *const u32 = transmute(rosie_engine.0);
        // //println!("BORK {}, {}, {:?}", pat_idx, messages.as_str(), my_ptr);

        println!("BORK {:?}", pat_idx);
        
        // //let result = rosie_match(rosie_engine, 0, 0, "\0".as_ptr(), &mut input_string, &mut match_result);

        // println!("BONK {:?}", match_result.data.ptr);



    

}


