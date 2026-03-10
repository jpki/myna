use crate::reader::MynaReader;

pub fn test(_app: &crate::App) {
    println!("OpenSSL version: {}", openssl::version::version());
    print!("Initialize: ");
    let mut reader = MynaReader::new().expect("Failed to initialize reader");
    println!("OK");
    print!("Connecting: ");
    let res = reader.connect();
    println!("res: {:?}", res);
    println!("OK");
}
