//! Small subsequence fuzzy matcher for the command palette.

/// Scores `candidate` against `query`; `None` when the query is not a subsequence. Higher is
/// better: consecutive runs, word starts and early matches score more, and a shorter candidate
/// wins ties. Matching ignores case; `_`, `-`, space and `:` count as word breaks.
pub fn score(query: &str, candidate: &str) -> Option<i32> {
    let q: Vec<char> = query
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    if q.is_empty() {
        return Some(0);
    }
    let cand: Vec<char> = candidate.chars().collect();
    let lower: Vec<char> = cand.iter().flat_map(|c| c.to_lowercase()).collect();
    if lower.len() != cand.len() {
        // Case folding changed the length (rare); fall back to a plain lowercase scan.
        return plain(&q, &candidate.to_lowercase());
    }
    let mut qi = 0;
    let mut total = 0i32;
    let mut prev_match: Option<usize> = None;
    for (i, &c) in lower.iter().enumerate() {
        if qi < q.len() && c == q[qi] {
            let mut s = 10;
            if prev_match == Some(i.wrapping_sub(1)) {
                s += 15;
            }
            let word_start = i == 0 || matches!(cand[i - 1], '_' | '-' | ' ' | ':' | '/');
            if word_start {
                s += 12;
            }
            if i == 0 {
                s += 6;
            }
            total += s - (i as i32).min(8);
            prev_match = Some(i);
            qi += 1;
        }
    }
    (qi == q.len()).then(|| total * 4 - cand.len() as i32)
}

fn plain(q: &[char], lower: &str) -> Option<i32> {
    let mut it = lower.chars();
    for &qc in q {
        it.find(|&c| c == qc)?;
    }
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_matches_everything() {
        assert_eq!(score("", "anything"), Some(0));
    }

    #[test]
    fn requires_subsequence() {
        assert!(score("rnm", "rename_symbol").is_some());
        assert!(score("zzz", "rename_symbol").is_none());
        assert!(score("lr", "rl").is_none());
    }

    #[test]
    fn prefers_prefix_word_starts_and_short() {
        let a = score("und", "undo").unwrap();
        let b = score("und", "undo_run").unwrap();
        let c = score("und", "set_function_bounds").unwrap_or(i32::MIN);
        assert!(a > b);
        assert!(b > c);
        let ws = score("rs", "rename_symbol").unwrap();
        let mid = score("rs", "versions").unwrap();
        assert!(ws > mid);
    }

    #[test]
    fn case_insensitive() {
        assert!(score("MAIN", "main").is_some());
        assert!(score("main", "MAIN").is_some());
    }
}
