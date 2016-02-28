extern crate gcc;

fn main() {
    gcc::compile_library("libtweetnacl.a", &["src/tweetnacl.c"]);
}
