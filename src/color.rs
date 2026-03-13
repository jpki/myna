pub fn black(s: impl std::fmt::Display) -> String {
    format!("\x1b[30m{}\x1b[0m", s)
}
pub fn red(s: impl std::fmt::Display) -> String {
    format!("\x1b[31m{}\x1b[0m", s)
}
pub fn green(s: impl std::fmt::Display) -> String {
    format!("\x1b[32m{}\x1b[0m", s)
}
pub fn yellow(s: impl std::fmt::Display) -> String {
    format!("\x1b[33m{}\x1b[0m", s)
}
pub fn blue(s: impl std::fmt::Display) -> String {
    format!("\x1b[34m{}\x1b[0m", s)
}
pub fn magenta(s: impl std::fmt::Display) -> String {
    format!("\x1b[35m{}\x1b[0m", s)
}
pub fn cyan(s: impl std::fmt::Display) -> String {
    format!("\x1b[36m{}\x1b[0m", s)
}
pub fn white(s: impl std::fmt::Display) -> String {
    format!("\x1b[37m{}\x1b[0m", s)
}
