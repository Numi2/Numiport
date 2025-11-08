#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(parts) = numiport::parse_packet(data) {
        let _ = numiport::build_aad(&parts.header, parts.tlv_bytes);
    }
});

