
# Rosie Rust Interface Overview
This crate implements a high-level interface to the [**Rosie**](https://rosie-lang.org/about/) matching engine for the [**Rosie Pattern Language**](https://gitlab.com/rosie-pattern-language/rosie/-/blob/master/README.md)\(`rpl`\).

Complete reference documentation for `rpl` is [here](https://gitlab.com/rosie-pattern-language/rosie/-/blob/master/doc/rpl.md),
and additional examples can be found [here](https://gitlab.com/rosie-pattern-language/rosie/-/blob/master/extra/examples/README.md).

## In Cargo.toml
To build Rosie as part of your project, add the following line to your Cargo.toml `[dependencies]` section:

`rosie = { features = ["build_static_librosie"] }`

To build Rosie to link against a shared librosie, already installed on the system, add the following line instead:

`rosie = { features = ["link_shared_librosie"] }`

## Deployment

Rosie depends on a `rosie_home` directory, containing support files including the Standard Pattern Library. See the
`Installation & Deployment` section of the [rosie_sys] crate's `README` for deployment instructions.

## Usage

There are 3 levels of depth at which you may access Rosie.

### High-Level: With `Rosie::match_str()`

Just one-line to check for a match
```rust
use rosie::*;

if Rosie::match_str("{ [H][^]* }", "Hello, Rosie!") {
    println!("It Matches!");
}
```
Or to get the matched substring
```rust
# use rosie::*;
let result : MatchResult = Rosie::match_str("date.any", "Nov 5, 1955! That was the day");
println!("Matched Substring = {}", result.matched_str());
assert_eq!(result.matched_str(), "Nov 5, 1955");
```

### Mid-Level: With compiled Patterns

Explicit compilation reduces overhead because you can manage compiled patterns yourself, dropping the patterns you don't need
and avoiding unnecessary recompilation.
```rust
use rosie::*;

let date_pat = Rosie::compile("date.us_long").unwrap();
let result : MatchResult = date_pat.match_str("Saturday, Nov 5, 1955").unwrap();
println!("did_match = {}", result.did_match());
println!("matched_str = {}", result.matched_str());
```

### Low-Level: With a RosieEngine

See [engine] for details.
