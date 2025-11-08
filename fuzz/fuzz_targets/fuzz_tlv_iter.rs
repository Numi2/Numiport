#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = numiport::TlvCursor::new(data);
    while let Some(item) = cursor.next() {
        if let Ok(tlv) = item {
            if tlv.type_id == numiport::TlvType::End as u8 {
                break;
            }
        } else {
            break;
        }
    }
});

