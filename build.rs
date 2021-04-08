
use std::process::Command;

extern crate pkg_config;
extern crate cc;


//Currently, this crate links to a version of the shared librosie library that is already installed on the system.
//  It will fail to build if librosie cannot be found.
//
//TODO: Test on Linux, Test on Windows
//
//TODO: It would be nice if this crate could support a static link option for librosie, as well as an option to pull
//  and build librosie from source.  It is unclear how best to implement that, given the dependencies of rosie on lua, etc.
//
//Kornel's reference guide to creating sys crates: https://kornel.ski/rust-sys-crate
//
fn main() {

    //First, see if we can locate the library using pkg_config
    let librosie = pkg_config::Config::new()
            .cargo_metadata(true)
            .print_system_libs(true)
            .probe("rosie");
    if librosie.is_ok() {
        //pkg_config should output the necessary output for cargo
        return;
    }

    //TODO: Test on Windows.  I suspect it won't work, and I may need to follow the example from Teseract,
    //  using the vcpkg crate, here:
    //https://github.com/ccouzens/tesseract-sys/blob/master/build.rs

    //If we haven't found it using one of the pkg trackers, try to compile the smoke.c file to "smoke it out"
    //Thanks to the zlib crate for this idea:  https://github.com/rust-lang/libz-sys/blob/main/build.rs
    let mut cfg = cc::Build::new();

    if librosie_installed(&mut cfg) {
        println!("cargo:rustc-link-lib=rosie");
        return;
    }


    panic!("Build Failure.  Couldn't find librosie");
    //TODO: I want to invoke make to build rosie from source, but that seems pointless because rosie needs to
    //  have its dependencies built manually when the build is invoked with make
    // let out_dir = env::var("OUT_DIR").unwrap();
    // Command::new("make").args(&["-C", "rosie-v1.2.2"])
    //                     .arg(&format!("O={}", out_dir)
    //                     .status().unwrap();
}


fn librosie_installed(cfg: &mut cc::Build) -> bool {
    let compiler = cfg.get_compiler();
    let mut cmd = Command::new(compiler.path());
    cmd.arg("src/smoke.c").arg("-o").arg("/dev/null").arg("-lrosie").arg("-lz");

    println!("running {:?}", cmd);
    if let Ok(status) = cmd.status() {
        if status.success() {
            return true;
        }
    }

    false
}
