
// This file contains items that are identical to items imported from the rosie-sys crate.
// This is done to work around the inability to document items with references to downstream crates.
// See:　https://users.rust-lang.org/t/rustdoc-circular-references-least-bad-work-around/65933
//  https://github.com/rust-lang/rust/issues/74481
//
//TODO: Get rid of this whole file, as soon as RustDoc gives us a way to document these items within the rosie-sys crate.

/// An error code from a Rosie operation 
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum RosieError {
    /// No error occurred.
    Success = 0,
    /// An unknown error occurred.
    MiscErr = -1,
    /// The Rosie Engine could not allocate the needed memory, either because the system allocator failed or because the limit
    /// set by [set_mem_alloc_limit](crate::engine::RosieEngine::set_mem_alloc_limit) was reached.  See [set_mem_alloc_limit](crate::engine::RosieEngine::set_mem_alloc_limit),
    /// [mem_alloc_limit](crate::engine::RosieEngine::mem_alloc_limit), and [mem_usage](crate::engine::RosieEngine::mem_usage) for more details.
    OutOfMemory = -2,
    /// A system API call failed.
    SysCallFailed = -3,
    /// A failure occurred in the `librosie` engine.
    EngineCallFailed = -4,
    /// An error related to a pattern input has occurred, for example, an `rpl` syntax error.
    ExpressionError = -1001,
    /// An error related to a package input has occurred, for example a missing package or `.rpl` file,
    /// a missing package declaration in the file, or another syntax error in the package.rpl file.
    PackageError = -1002,
    /// An invalid argument was passed to a rosie function.
    ArgError = -1003,
}

impl RosieError {
    pub fn from(code: i32) -> Self {
        match code {
            0 => RosieError::Success,
            -2 => RosieError::OutOfMemory,
            -3 => RosieError::SysCallFailed,
            -4 => RosieError::EngineCallFailed,
            -1001 => RosieError::ExpressionError,
            -1002 => RosieError::PackageError,
            -1003 => RosieError::ArgError,
            _ => RosieError::MiscErr
        }
    }
}
