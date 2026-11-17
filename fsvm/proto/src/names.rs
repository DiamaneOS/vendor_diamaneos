// Copyright (C) 2026 DiamaneOS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! File name rules. Names come from a filesystem an attacker may have crafted, so every name the VM returns is
//! checked here before Android sees it, and names Android sends are held to the same rules so that nothing can be
//! created that would be refused when listed.

/// Longest name in bytes. exFAT allows 255 UTF-16 units, which is at most 765 bytes of UTF-8 for characters in the
/// Basic Multilingual Plane and 1020 bytes when every unit pair is a supplementary character. FUSE allows 1024.
pub const MAX_NAME_BYTES: usize = 1020;

/// Longest name in UTF-16 units, as exFAT and long FAT names count them.
pub const MAX_NAME_UNITS: usize = 255;

/// Why a name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong,
    NotUtf8,
    DotOrDotDot,
    Forbidden(char),
}

/// Characters a name may not contain. Separators and NUL would break paths. Control characters, bidirectional
/// controls, zero-width characters and line separators can make a name look like another name or hide its
/// extension (for example "photo\u{202E}gpj.exe"). `:` and `\` are refused by FAT and exFAT themselves, so a name
/// holding one did not come from an honest filesystem.
pub fn is_forbidden(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{1F}' | '\u{7F}' | // C0 controls and DEL
        '\u{80}'..='\u{9F}' |           // C1 controls
        '/' | '\\' | ':' |
        '\u{61C}' |                     // Arabic letter mark
        '\u{200B}'..='\u{200F}' |       // zero-width space, joiners, LRM, RLM
        '\u{2028}' | '\u{2029}' |       // line and paragraph separator
        '\u{202A}'..='\u{202E}' |       // bidi embeddings and overrides
        '\u{2060}'..='\u{2064}' |       // word joiner and invisible operators
        '\u{2066}'..='\u{2069}' |       // bidi isolates
        '\u{FEFF}' |                    // zero-width no-break space
        '\u{FFF9}'..='\u{FFFB}'         // interlinear annotation controls
    )
}

/// Checks one name and returns it as a string.
pub fn check_name(raw: &[u8]) -> Result<&str, NameError> {
    if raw.is_empty() {
        return Err(NameError::Empty);
    }
    if raw.len() > MAX_NAME_BYTES {
        return Err(NameError::TooLong);
    }
    let name = std::str::from_utf8(raw).map_err(|_| NameError::NotUtf8)?;
    if name == "." || name == ".." {
        return Err(NameError::DotOrDotDot);
    }
    let mut units = 0usize;
    for c in name.chars() {
        if is_forbidden(c) {
            return Err(NameError::Forbidden(c));
        }
        units += c.len_utf16();
    }
    if units > MAX_NAME_UNITS {
        return Err(NameError::TooLong);
    }
    Ok(name)
}

/// The key two names collide under. FAT and exFAT compare names without case, so two entries that differ only in
/// case cannot both exist on an honest card. Lowercasing is close to the filesystems' own upcase tables and errs
/// toward treating more names as equal, which only drops entries a crafted card added.
pub fn collision_key(name: &str) -> String {
    name.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names_pass() {
        for n in ["DCIM", "photo.jpg", "Ünïcödé", "日本語のファイル.txt", "a b c", "x*?\"<>|", "😀.png"] {
            assert_eq!(check_name(n.as_bytes()), Ok(n), "{n}");
        }
    }

    #[test]
    fn exfat_length_limit_counts_utf16_units() {
        // 255 three-byte characters: 765 bytes, 255 units, legal on exFAT.
        let ok: String = std::iter::repeat('語').take(255).collect();
        assert_eq!(ok.len(), 765);
        assert!(check_name(ok.as_bytes()).is_ok());
        let long: String = std::iter::repeat('語').take(256).collect();
        assert_eq!(check_name(long.as_bytes()), Err(NameError::TooLong));
        // Supplementary characters take two units each: 127 fit, 128 do not.
        let emoji: String = std::iter::repeat('😀').take(127).collect();
        assert!(check_name(emoji.as_bytes()).is_ok());
        let emoji: String = std::iter::repeat('😀').take(128).collect();
        assert_eq!(check_name(emoji.as_bytes()), Err(NameError::TooLong));
        // 255 ASCII characters are fine, 256 are not.
        assert!(check_name("a".repeat(255).as_bytes()).is_ok());
        assert_eq!(check_name("a".repeat(256).as_bytes()), Err(NameError::TooLong));
        assert_eq!(check_name(&vec![b'a'; MAX_NAME_BYTES + 1]), Err(NameError::TooLong));
    }

    #[test]
    fn refused_names() {
        assert_eq!(check_name(b""), Err(NameError::Empty));
        assert_eq!(check_name(b"."), Err(NameError::DotOrDotDot));
        assert_eq!(check_name(b".."), Err(NameError::DotOrDotDot));
        assert_eq!(check_name(b"a/b"), Err(NameError::Forbidden('/')));
        assert_eq!(check_name(b"a\\b"), Err(NameError::Forbidden('\\')));
        assert_eq!(check_name(b"c:x"), Err(NameError::Forbidden(':')));
        assert_eq!(check_name(b"a\0b"), Err(NameError::Forbidden('\0')));
        assert_eq!(check_name(b"a\nb"), Err(NameError::Forbidden('\n')));
        assert_eq!(check_name(b"a\x7fb"), Err(NameError::Forbidden('\x7f')));
        assert_eq!(check_name(&[0xff, 0xfe]), Err(NameError::NotUtf8));
        assert_eq!(check_name(&[b'a', 0xc0, 0x80]), Err(NameError::NotUtf8)); // overlong NUL
        for c in ['\u{85}', '\u{9B}', '\u{61C}', '\u{200B}', '\u{200D}', '\u{200E}', '\u{2028}', '\u{2029}', '\u{202A}',
                  '\u{202E}', '\u{2060}', '\u{2066}', '\u{2069}', '\u{FEFF}', '\u{FFFB}'] {
            let n = format!("photo{c}gpj.exe");
            assert_eq!(check_name(n.as_bytes()), Err(NameError::Forbidden(c)), "{c:?}");
        }
        // A leading or trailing dot alone is fine, only "." and ".." are refused.
        assert!(check_name(b".hidden").is_ok());
        assert!(check_name(b"...").is_ok());
    }

    #[test]
    fn collisions_ignore_case() {
        assert_eq!(collision_key("Photo.JPG"), collision_key("photo.jpg"));
        assert_ne!(collision_key("a"), collision_key("b"));
    }
}
