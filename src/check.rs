use pcsc::{
    Context, Disposition, Protocol, Protocols, ReaderState, Scope, ShareMode, State, Status,
};
use std::ffi::CString;

pub fn main(app: &crate::App) {
    println!("OpenSSL version: {}", openssl::version::version());

    print!("SCardEstablishContext: ");
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => {
            println!("OK");
            ctx
        }
        Err(err) => {
            println!("NG {}", err);
            return;
        }
    };

    let readers = match list_readers(&ctx) {
        Some(readers) => readers,
        None => {
            release_context(ctx);
            return;
        }
    };

    if readers.is_empty() {
        println!("No PC/SC readers found.");
        release_context(ctx);
        return;
    }

    for (i, reader) in readers.iter().enumerate() {
        println!("  Reader {}: {}", i, reader.to_string_lossy());
    }

    let reader = match select_reader(app, &readers) {
        Some(reader) => reader,
        None => {
            release_context(ctx);
            return;
        }
    };

    println!("  SelectedReader: {}", reader.to_string_lossy());
    test_status_change(&ctx, reader);
    test_card(&ctx, reader);
    release_context(ctx);
}

fn list_readers(ctx: &Context) -> Option<Vec<CString>> {
    print!("SCardListReaders: ");
    match ctx.list_readers_owned() {
        Ok(readers) => {
            println!("OK");
            Some(readers)
        }
        Err(err) => {
            println!("NG {}", err);
            None
        }
    }
}

fn select_reader<'a>(app: &crate::App, readers: &'a [CString]) -> Option<&'a CString> {
    match selected_reader_name(app) {
        Some(name) => match readers
            .iter()
            .find(|reader| reader.to_string_lossy() == name)
        {
            Some(reader) => Some(reader),
            None => {
                println!("Reader not found: {}", name);
                None
            }
        },
        None => readers.first(),
    }
}

fn selected_reader_name(app: &crate::App) -> Option<&str> {
    match &app.command {
        crate::Commands::Check(args) => args.name.as_deref(),
        _ => None,
    }
}

fn test_status_change(ctx: &Context, reader: &CString) {
    print!("SCardGetStatusChange: ");
    let mut states = [ReaderState::new(reader.clone(), State::UNAWARE)];
    match ctx.get_status_change(None, &mut states) {
        Ok(()) => {
            println!("OK");
            print_reader_state(&states[0]);
        }
        Err(err) => {
            println!("NG {}", err);
        }
    }
}

fn print_reader_state(state: &ReaderState) {
    println!("  Reader: {}", state.name().to_string_lossy());
    print_state_flags("CurrentState", state.current_state());
    print_state_flags("EventState", state.event_state());
    println!("  EventCount: {}", state.event_count());
    if !state.atr().is_empty() {
        println!("  Atr: {}", format_hex(state.atr()));
    }
}

fn print_state_flags(label: &str, state: State) {
    println!("  {}: 0x{:08x}", label, state.bits());
    for (flag, name) in [
        (State::IGNORE, "STATE_IGNORE"),
        (State::CHANGED, "STATE_CHANGED"),
        (State::UNKNOWN, "STATE_UNKNOWN"),
        (State::UNAVAILABLE, "STATE_UNAVAILABLE"),
        (State::EMPTY, "STATE_EMPTY"),
        (State::PRESENT, "STATE_PRESENT"),
        (State::ATRMATCH, "STATE_ATRMATCH"),
        (State::EXCLUSIVE, "STATE_EXCLUSIVE"),
        (State::INUSE, "STATE_INUSE"),
        (State::MUTE, "STATE_MUTE"),
        (State::UNPOWERED, "STATE_UNPOWERED"),
    ] {
        if state.contains(flag) {
            println!("    {}", name);
        }
    }
}

fn test_card(ctx: &Context, reader: &CString) {
    let card = match connect_card(ctx, reader) {
        Some(card) => card,
        None => return,
    };

    print!("SCardStatus: ");
    match card.status2_owned() {
        Ok(status) => {
            println!("OK");
            for (i, name) in status.reader_names().iter().enumerate() {
                println!("  StatusReader {}: {}", i, name.to_string_lossy());
            }
            print_card_status_flags(status.status());
            match status.protocol2() {
                Some(protocol) => println!("  ActiveProtocol: {}", protocol_name(protocol)),
                None => println!("  ActiveProtocol: none"),
            }
            println!("  Atr: {}", format_hex(status.atr()));
        }
        Err(err) => {
            println!("NG {}", err);
        }
    }

    print!("SCardDisconnect: ");
    match card.disconnect(Disposition::ResetCard) {
        Ok(()) => println!("OK"),
        Err((_card, err)) => println!("NG {}", err),
    }
}

fn connect_card(ctx: &Context, reader: &CString) -> Option<pcsc::Card> {
    print!("SCardConnect: ");
    match ctx.connect(reader.as_c_str(), ShareMode::Shared, Protocols::ANY) {
        Ok(card) => {
            println!("OK");
            Some(card)
        }
        Err(err) => {
            println!("NG {}", err);
            None
        }
    }
}

fn print_card_status_flags(status: Status) {
    println!("  State: 0x{:08x}", status.bits());
    for (flag, name) in [
        (Status::UNKNOWN, "SCARD_UNKNOWN"),
        (Status::ABSENT, "SCARD_ABSENT"),
        (Status::PRESENT, "SCARD_PRESENT"),
        (Status::SWALLOWED, "SCARD_SWALLOWED"),
        (Status::POWERED, "SCARD_POWERED"),
        (Status::NEGOTIABLE, "SCARD_NEGOTIABLE"),
        (Status::SPECIFIC, "SCARD_SPECIFIC"),
    ] {
        if status.contains(flag) {
            println!("    {}", name);
        }
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::T0 => "T=0",
        Protocol::T1 => "T=1",
        Protocol::RAW => "RAW",
    }
}

fn release_context(ctx: Context) {
    print!("SCardReleaseContext: ");
    match ctx.release() {
        Ok(()) => println!("OK"),
        Err((_ctx, err)) => println!("NG {}", err),
    }
}

fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(" ")
}
