//! Two repo-wide invariants, both walked from the workspace root.
//!
//! 1. **No estate identifiers.** holofote is public and generic. A company,
//!    tenant, hostname, environment codename or person name has no business
//!    in it — and the test that enforces that cannot itself contain the
//!    names, or it would be the leak. So the denylist is embedded as BLAKE3
//!    hashes of the lowercased tokens, computed once offline; every token in
//!    every file that ships is hashed and compared, and so is every window
//!    of `WINDOW_MIN..=WINDOW_MAX` bytes inside a token, so a denied word
//!    embedded in a compound identifier is caught too. A hit reports the
//!    file and the matched text so the fix is obvious, and that text is only
//!    ever printed on a red run.
//!
//!    The walk reaches everything git ships — source, docs, manifests,
//!    lock files, workflows, the licence, dotfiles — because workflows and
//!    lock files are exactly where runner labels, secret names and org paths
//!    land. It skips build output, the VCS store, symlinks (a `result` link
//!    points into the Nix store) and the generated files named in
//!    `.gitignore`; a test pins that every skipped name IS gitignored.
//!
//! 2. **Typed emission.** No non-test source contains a `format!` macro
//!    call — nor its hand-expansions, `format_args!(…)` and
//!    `fmt::format(…)`. Every emitted string is a `Display` / `write!`, a
//!    `thiserror` message, a `tracing` event, or serde output. The needles
//!    are spelled here in pieces so this file does not trip its own check.
//!    `#[cfg(test)] mod … { … }` blocks are cut out before the search, so a
//!    test module may use plain `format!`; a `#[cfg(test)]` on anything but
//!    a `mod` is left in and scanned.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// BLAKE3 hex of each denied token, lowercased. Twelve entries.
const DENIED: [&str; 12] = [
    "10c979c156388867b5ad2cb06f26cd0c44144c591c3abf4f18c9c622a5f00818",
    "b46027b5464008dd28e9e4cd0959c5c9ede86f78ed5e30dee5585813caaf2cbd",
    "aaf760aef5056ebb47f150f1131622cbab979b65e26fd0492b6f740568977f46",
    "7176780d4ade1ed1c43edca5ff26325facd0bdeff16e78b7b144f5469067f08c",
    "e922d56e6e1a3cf2834e98bd26d6ac4f5159e3b0bd672f32d8e4c2ff8ffb6a2a",
    "8e8a8bacf757d1b55e9700c8238aa49b1ff49740ebce7de09fa225d8364262fc",
    "cf819caee067aae1ca0453c269789d7ebd0bcb79a2a8f8e44838e38a44ed0b41",
    "656d2858136c1c4ac69744c637c7450de43c4854fdcdcfb1a0f8e186270ca3f6",
    "5d0ef795b2ef4f66eb4033d5e8265fb2c069ffacc839a1186f437a2d9732a7d0",
    "e18d0f48c6c3561337355ec5081d155c190741b3dd750a9eff50ea966ca03bab",
    "9c3fc7c5fec1803afdb49697f40c2ddc57dd69f1ecaac2ba2a52c3e8e2245c0c",
    "9aa1a1be5148b9e00fac93f21b8f1aba5fbb1249382a4c78e8788364b65161da",
];

/// Extensions the identifier walk covers. A file with NO extension
/// (`LICENSE`, `.gitignore`) is covered too — see [`is_shipped_text`].
const SOURCE_LIKE: [&str; 9] = [
    "rs", "md", "toml", "nix", "lisp", "yml", "yaml", "json", "lock",
];

/// Directories never walked: build output and the VCS store.
const SKIPPED_DIRS: [&str; 3] = ["target", ".git", "node_modules"];

/// Generated files that sit in the tree but do not ship. Each MUST be
/// named verbatim in `.gitignore` — `every_skipped_file_is_gitignored`
/// fails otherwise — so this list can never hide a file git would commit.
const GENERATED_FILES: [&str; 1] = ["Cargo.build-spec.json"];

/// Windows inside a token that are hashed besides the whole token. Below
/// four bytes a window would match inside too many ordinary words; above
/// thirty-two no name is plausible. A denied token shorter than the
/// minimum is still caught as a whole token.
const WINDOW_MIN: usize = 4;
const WINDOW_MAX: usize = 32;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<root>/holofote`; the workspace root is its parent.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives one level below the workspace root")
        .to_path_buf()
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
}

fn walk(dir: &Path, keep: &dyn Fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        let name = file_name(&path);
        // A symlink points outside the tree (a Nix `result` link points
        // into the store); what it names is not ours and is not walked.
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            if !SKIPPED_DIRS.contains(&name) {
                walk(&path, keep, out);
            }
        } else if !GENERATED_FILES.contains(&name) && keep(&path) {
            out.push(path);
        }
    }
}

/// Everything git ships as text: a source-like extension, or none at all.
fn is_shipped_text(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => SOURCE_LIKE.contains(&ext),
        None => true,
    }
}

fn shipped_text_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk(&workspace_root(), &is_shipped_text, &mut files);
    files.sort();
    files
}

/// Split on every non-alphanumeric byte, lowercase, dedupe.
fn tokens_of(text: &str) -> HashSet<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn is_denied(text: &str, denied: &HashSet<&str>) -> bool {
    denied.contains(blake3::hash(text.as_bytes()).to_hex().as_str())
}

/// The denied text inside `token`, if any: the whole token, or a window of
/// `WINDOW_MIN..=WINDOW_MAX` bytes of it. Tokens are ASCII alphanumeric, so
/// byte windows are char windows.
fn denied_in(token: &str, denied: &HashSet<&str>) -> Option<String> {
    if is_denied(token, denied) {
        return Some(token.to_owned());
    }
    let longest = WINDOW_MAX.min(token.len().saturating_sub(1));
    for len in WINDOW_MIN..=longest {
        for start in 0..=token.len() - len {
            let window = &token[start..start + len];
            if is_denied(window, denied) {
                return Some(window.to_owned());
            }
        }
    }
    None
}

#[test]
fn the_walk_reaches_every_member_and_the_root_manifests() {
    let files = shipped_text_files();
    let root = workspace_root();
    let rel: Vec<String> = files
        .iter()
        .map(|f| {
            f.strip_prefix(&root)
                .expect("under root")
                .display()
                .to_string()
        })
        .collect();
    for must in [
        "Cargo.toml",
        "Cargo.lock",
        "Cargo.gen.lock",
        "README.md",
        "CLAUDE.md",
        "LICENSE",
        ".gitignore",
        "caixa.lisp",
        "flake.nix",
        ".github/workflows/auto-release.yml",
        ".github/workflows/gen-spec.yml",
        "holofote/src/lib.rs",
        "holofote/src/client.rs",
        "holofote/specs/holofote.lisp",
        "holofote-mcp/src/main.rs",
        "tests/no_estate_identifiers.rs",
    ] {
        assert!(
            rel.iter().any(|r| r == must || r.ends_with(must)),
            "the walk must reach {must}; saw {rel:?}"
        );
    }
    assert!(
        rel.iter().all(|r| !r.starts_with("target/")),
        "build output must not be walked"
    );
    for generated in GENERATED_FILES {
        assert!(
            rel.iter().all(|r| file_name(Path::new(r)) != generated),
            "{generated} is generated and must not be walked"
        );
    }
}

/// The skip list cannot hide a shipped file: every name on it is a verbatim
/// line of `.gitignore`.
#[test]
fn every_skipped_file_is_gitignored() {
    let gitignore = fs::read_to_string(workspace_root().join(".gitignore")).expect(".gitignore");
    let lines: HashSet<&str> = gitignore.lines().map(str::trim).collect();
    for generated in GENERATED_FILES {
        assert!(
            lines.contains(generated),
            "{generated} is skipped by the walk but not ignored by git"
        );
    }
}

#[test]
fn no_shipped_text_file_carries_an_estate_identifier() {
    let denied: HashSet<&str> = DENIED.iter().copied().collect();
    let mut hits: Vec<String> = Vec::new();
    for file in shipped_text_files() {
        let text =
            fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for token in tokens_of(&text) {
            if let Some(matched) = denied_in(&token, &denied) {
                hits.push(format!(
                    "{}: token `{token}` carries `{matched}`",
                    file.display()
                ));
            }
        }
    }
    hits.sort();
    assert!(
        hits.is_empty(),
        "estate identifiers found:\n{}",
        hits.join("\n")
    );
}

/// The denylist itself is sound: twelve distinct 64-hex entries, and a
/// neutral token used throughout the docs is NOT on it — so a green run is
/// not the hash comparison silently matching nothing.
#[test]
fn the_denylist_is_well_formed_and_does_not_deny_the_neutral_labels() {
    let distinct: HashSet<&str> = DENIED.iter().copied().collect();
    assert_eq!(distinct.len(), DENIED.len());
    for h in DENIED {
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    for neutral in ["alpha", "beta", "example", "splunk", "holofote", "observer"] {
        assert!(
            denied_in(neutral, &distinct).is_none(),
            "{neutral} must not be denied"
        );
    }
}

/// The matcher, against a denylist made here from neutral words: a denied
/// word is caught whole, embedded in a compound, and at either end; a
/// near-miss is not; a word shorter than the window is caught whole only.
#[test]
fn the_matcher_finds_a_denied_word_inside_a_compound_token() {
    let sentinel = blake3::hash(b"zzsentinel").to_hex();
    let short = blake3::hash(b"zqx").to_hex();
    let denied: HashSet<&str> = [sentinel.as_str(), short.as_str()].into_iter().collect();
    for hit in [
        "zzsentinel",
        "zzsentinellabs",
        "corpzzsentinel",
        "corpzzsentinellabs",
    ] {
        assert_eq!(
            denied_in(hit, &denied).as_deref(),
            Some("zzsentinel"),
            "{hit}"
        );
    }
    for miss in ["zzsentine", "zsentinel", "sentinel", "zz", ""] {
        assert!(denied_in(miss, &denied).is_none(), "{miss}");
    }
    assert_eq!(denied_in("zqx", &denied).as_deref(), Some("zqx"));
    assert!(
        denied_in("xzqxx", &denied).is_none(),
        "below WINDOW_MIN a denied word is caught whole only"
    );
    let long = "a".repeat(WINDOW_MAX + 8);
    assert!(denied_in(&long, &denied).is_none());
}

// ── typed emission ─────────────────────────────────────────────────────

fn is_non_test_rust_source(path: &Path) -> bool {
    let is_rs = path.extension().and_then(|e| e.to_str()) == Some("rs");
    let in_tests_dir = path.components().any(|c| c.as_os_str() == "tests");
    is_rs && !in_tests_dir
}

/// Index just past a `"…"` literal that opens at `open`.
fn past_string(b: &[u8], open: usize) -> usize {
    let mut i = open + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

/// Index just past a raw string `r#*"…"#*` whose `r` is at `at`, if one
/// opens there.
fn past_raw_string(b: &[u8], at: usize) -> Option<usize> {
    let ident_before = at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
    let prefixed = at > 0
        && matches!(b[at - 1], b'b' | b'c')
        && !(at > 1 && (b[at - 2].is_ascii_alphanumeric() || b[at - 2] == b'_'));
    if ident_before && !prefixed {
        return None;
    }
    let hashes = b[at + 1..].iter().take_while(|&&c| c == b'#').count();
    let quote = at + 1 + hashes;
    if b.get(quote) != Some(&b'"') {
        return None;
    }
    let mut i = quote + 1;
    while i < b.len() {
        if b[i] == b'"' && b[i + 1..].iter().take(hashes).all(|&c| c == b'#') {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(b.len())
}

/// Index just past a char literal opening at `at`, or `None` for a
/// lifetime / label (`'a`).
fn past_char(b: &[u8], at: usize) -> Option<usize> {
    match b.get(at + 1) {
        Some(b'\\') => {
            let mut i = at + 3;
            while i < b.len() && b[i] != b'\'' {
                i += 1;
            }
            Some(i + 1)
        }
        Some(&c) if c >= 0x80 => {
            let end = (at + 2..b.len().min(at + 6)).find(|&i| b[i] == b'\'')?;
            Some(end + 1)
        }
        Some(_) if b.get(at + 2) == Some(&b'\'') => Some(at + 3),
        _ => None,
    }
}

/// Index just past a `/* … */` comment (nested, as Rust nests them).
fn past_block_comment(b: &[u8], at: usize) -> usize {
    let mut depth = 0usize;
    let mut i = at;
    while i + 1 < b.len() {
        if b[i] == b'/' && b[i + 1] == b'*' {
            depth += 1;
            i += 2;
        } else if b[i] == b'*' && b[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    b.len()
}

/// The `{ … }` block that begins at or after `from`, as `(open, past_close)`,
/// skipping braces inside strings, chars and comments.
fn block_after(b: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    let mut depth = 0usize;
    let mut open = None;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => i = past_block_comment(b, i),
            b'"' => i = past_string(b, i),
            b'r' => i = past_raw_string(b, i).unwrap_or(i + 1),
            b'\'' => i = past_char(b, i).unwrap_or(i + 1),
            b'{' => {
                depth += 1;
                open.get_or_insert(i);
                i += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
                if depth == 0
                    && let Some(o) = open
                {
                    return Some((o, i));
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// `text` with every `#[cfg(test)]` `mod` block removed.
fn without_test_modules(text: &str) -> String {
    const MARKER: &str = "#[cfg(test)]";
    let b = text.as_bytes();
    let mut out = String::new();
    let mut cursor = 0;
    while let Some(found) = text[cursor..].find(MARKER) {
        let at = cursor + found;
        let after = at + MARKER.len();
        let is_mod = text[after..].trim_start().starts_with("mod ");
        if let (true, Some((_, past_close))) = (is_mod, block_after(b, after)) {
            out.push_str(&text[cursor..at]);
            cursor = past_close;
        } else {
            out.push_str(&text[cursor..after]);
            cursor = after;
        }
    }
    out.push_str(&text[cursor..]);
    out
}

/// The three spellings of an untyped emission, assembled at runtime so
/// this file never contains them verbatim.
fn emission_needles() -> [String; 3] {
    let bang = String::from("!(");
    [
        String::from("format") + &bang,
        String::from("format_args") + &bang,
        String::from("fmt::format") + "(",
    ]
}

#[test]
fn no_non_test_source_calls_the_format_macro_or_its_expansions() {
    let needles = emission_needles();
    let mut files = Vec::new();
    walk(&workspace_root(), &is_non_test_rust_source, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("src/client.rs"))
            && files.iter().any(|f| f.ends_with("src/main.rs")),
        "the ban must reach both members: {files:?}"
    );
    let mut offenders: Vec<String> = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
        let shipped = without_test_modules(&text);
        for needle in &needles {
            if shipped.contains(needle.as_str()) {
                offenders.push(format!("{}: {needle}", f.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the typed-emission ban is broken in:\n{}",
        offenders.join("\n")
    );
}

/// The stripper removes exactly the `#[cfg(test)] mod` block — braces in
/// strings, chars and comments do not end it early, a `#[cfg(test)]` on
/// anything but a `mod` stays, and code after the module is still seen.
#[test]
fn the_test_module_stripper_cuts_the_block_and_nothing_else() {
    let needle = &emission_needles()[0];
    let src = [
        "fn shipped() {}\n",
        "#[cfg(test)]\nmod tests {\n",
        "    const S: &str = \"}\"; const R: &str = r#\"}\"#; const C: char = '}';\n",
        "    // } in a comment\n    /* } in a /* nested */ block */\n",
        "    fn t() { let _ = ",
        needle,
        "\"{}\", 1); }\n}\n",
        "fn also_shipped() { let _x = ",
        needle,
        "\"x\"); }\n",
        "#[cfg(test)]\nfn helper() { let _ = ",
        needle,
        "\"y\"); }\n",
    ]
    .concat();
    let stripped = without_test_modules(&src);
    assert!(stripped.contains("fn shipped() {}"));
    assert!(!stripped.contains("mod tests"), "{stripped}");
    assert!(!stripped.contains("nested"), "{stripped}");
    assert!(
        stripped.contains("fn also_shipped()"),
        "code after the module is kept: {stripped}"
    );
    assert!(
        stripped.contains("fn helper()"),
        "a cfg(test) that is not a mod is kept: {stripped}"
    );
    assert_eq!(
        stripped.matches(needle.as_str()).count(),
        2,
        "the two shipped needles survive, the one in the module does not: {stripped}"
    );
    assert_eq!(without_test_modules("no tests here"), "no tests here");
}
