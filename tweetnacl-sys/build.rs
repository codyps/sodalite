extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/tweetnacl.c")
        .compile("libtweetnacl.a");
}
