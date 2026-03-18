use std::str::FromStr;
fn main() {
    let addr = bitcoin::Address::from_str("1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv").unwrap();
    println!("{:?}", addr);
}
