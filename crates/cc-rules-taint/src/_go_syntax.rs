//! Private Go source-syntax helpers shared across the Phase-10 gosec
//! probes. Keeping them here means S5 (one canonical name per concept)
//! holds: `contains_unquoted_plus` and `first_arg_slice` exist exactly
//! once.

/// Return everything from `s` up to the comma at depth 1 or the
/// matching closing paren — i.e. the first argument of a Go call.
#[must_use]
pub(crate) fn first_arg_slice(s: &str) -> &str {
    let mut depth: i32 = 1;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &s[..i];
                }
            }
            ',' if depth == 1 => return &s[..i],
            _ => {}
        }
    }
    s
}

/// True iff `s` contains a `+` character outside any double-quoted
/// string literal. Uses a small state machine to track whether the
/// scanner is currently inside `"..."`, honouring `\\` escape pairs so
/// `"a\""` does not look closed prematurely.
#[must_use]
pub(crate) fn contains_unquoted_plus(s: &str) -> bool {
    let mut state = ScanState::Bare;
    for c in s.chars() {
        state = step(state, c);
        if matches!(state, ScanState::Hit) {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy)]
enum ScanState {
    Bare,
    InString,
    Escape,
    Hit,
}

fn step(state: ScanState, c: char) -> ScanState {
    match state {
        ScanState::Bare => step_bare(c),
        ScanState::InString => step_in_string(c),
        ScanState::Escape => ScanState::InString,
        ScanState::Hit => ScanState::Hit,
    }
}

fn step_bare(c: char) -> ScanState {
    if c == '+' {
        ScanState::Hit
    } else if c == '"' {
        ScanState::InString
    } else {
        ScanState::Bare
    }
}

fn step_in_string(c: char) -> ScanState {
    if c == '\\' {
        ScanState::Escape
    } else if c == '"' {
        ScanState::Bare
    } else {
        ScanState::InString
    }
}
