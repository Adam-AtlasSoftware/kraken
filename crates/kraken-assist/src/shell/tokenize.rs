//! A small POSIX-ish splitter for shell command lines: quoting (single, double, backslash),
//! pipes, and a list of the syntax that makes a line "complex" (anything but a plain pipeline).
//! It does not run or expand anything; it only finds the words of each command so the policy
//! can look at the programs.

/// A command line cut into pipeline segments.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Parsed {
    /// The words of each command, quotes removed. For a complex line these are a best effort:
    /// every place a new command can start (`;`, `&&`, `$(`, a backtick, `(`) starts a segment,
    /// so the policy can still look at the program of each.
    pub segments: Vec<Vec<String>>,
    /// Why the line is more than a pipeline of simple commands (the first reason found).
    pub complex: Option<String>,
}

impl Parsed {
    /// True when the line is only simple commands joined by `|`.
    pub fn is_simple(&self) -> bool {
        self.complex.is_none()
    }
}

#[derive(Default)]
struct Builder {
    segments: Vec<Vec<String>>,
    words: Vec<String>,
    word: String,
    in_word: bool,
    complex: Option<String>,
    nested: Vec<Vec<String>>,
}

impl Builder {
    fn flag(&mut self, why: &str) {
        if self.complex.is_none() {
            self.complex = Some(why.to_string());
        }
    }

    fn end_word(&mut self) {
        if self.in_word {
            self.words.push(std::mem::take(&mut self.word));
            self.in_word = false;
        }
    }

    fn end_segment(&mut self) {
        self.end_word();
        if self.words.is_empty() {
            self.flag("an empty command");
        } else {
            self.segments.push(std::mem::take(&mut self.words));
        }
    }

    /// A separator that is not a pipe: a new command starts, and the line is not simple.
    fn split(&mut self, why: &str) {
        self.flag(why);
        self.end_word();
        if !self.words.is_empty() {
            self.segments.push(std::mem::take(&mut self.words));
        }
    }

    /// A command substitution inside double quotes: its text, up to the closing quote, is parsed
    /// as a line of its own. Returns where the quote loop goes on.
    fn nested(&mut self, chars: &[char], from: usize, why: &str) -> usize {
        self.flag(why);
        let end = chars[from..]
            .iter()
            .position(|c| *c == '"')
            .map_or(chars.len(), |p| from + p);
        let inner: String = chars[from..end].iter().collect();
        self.nested
            .extend(parse(inner.trim_end_matches([')', '`'])).segments);
        end
    }

    fn push(&mut self, c: char) {
        self.word.push(c);
        self.in_word = true;
    }
}

/// Splits `line`.
pub fn parse(line: &str) -> Parsed {
    let chars: Vec<char> = line.chars().collect();
    let mut b = Builder::default();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            '\'' => {
                b.in_word = true;
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('\'') => break,
                        Some(&q) => b.word.push(q),
                        None => {
                            b.flag("an unclosed quote");
                            break;
                        }
                    }
                    i += 1;
                }
            }
            '"' => {
                b.in_word = true;
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('"') => break,
                        Some('\\') => {
                            match chars.get(i + 1) {
                                Some(&n) if matches!(n, '"' | '\\' | '$' | '`') => {
                                    b.word.push(n);
                                    i += 1;
                                }
                                Some('\n') => {
                                    b.flag("a line break");
                                    i += 1;
                                }
                                _ => b.word.push('\\'),
                            };
                        }
                        Some('`') => {
                            i = b.nested(&chars, i + 1, "a backtick");
                            continue;
                        }
                        Some('$') => {
                            let n = chars.get(i + 1).copied();
                            match n {
                                Some('(') => {
                                    i = b.nested(&chars, i + 2, "`$(`");
                                    continue;
                                }
                                Some('{') => {
                                    b.flag("`${`");
                                    b.word.push('$');
                                }
                                Some(x) if x == '_' || x.is_ascii_alphanumeric() => {
                                    b.flag("a `$` variable");
                                    b.word.push('$');
                                }
                                Some('?' | '$' | '!' | '#' | '@' | '*' | '-') => {
                                    b.flag("a `$` variable");
                                    b.word.push('$');
                                }
                                _ => b.word.push('$'),
                            }
                        }
                        Some(&q) => b.word.push(q),
                        None => {
                            b.flag("an unclosed quote");
                            break;
                        }
                    }
                    i += 1;
                }
            }
            '\\' => match next {
                Some('\n') => {
                    b.flag("a line break");
                    i += 1;
                }
                Some(n) => {
                    b.push(n);
                    i += 1;
                }
                None => b.push('\\'),
            },
            ' ' | '\t' => b.end_word(),
            '\n' | '\r' => b.split("a line break"),
            '|' => {
                if next == Some('|') {
                    b.split("`||`");
                    i += 1;
                } else {
                    b.end_segment();
                    if next == Some('&') {
                        b.flag("`|&`");
                        i += 1;
                    }
                }
            }
            '&' => {
                if next == Some('&') {
                    b.split("`&&`");
                    i += 1;
                } else {
                    b.split("`&`");
                }
            }
            ';' => b.split("`;`"),
            '>' => {
                b.split(if next == Some('>') { "`>>`" } else { "`>`" });
                if next == Some('>') {
                    i += 1;
                }
            }
            '<' => {
                b.split(if next == Some('<') { "`<<`" } else { "`<`" });
                if next == Some('<') {
                    i += 1;
                }
            }
            '`' => b.split("a backtick"),
            '(' | ')' | '{' | '}' => b.split("a subshell or brace group"),
            '$' => match next {
                Some('(') => {
                    b.split("`$(`");
                    i += 1;
                }
                Some('{') => {
                    b.flag("`${`");
                    b.push('$');
                }
                Some(x) if x == '_' || x.is_ascii_alphanumeric() => {
                    b.flag("a `$` variable");
                    b.push('$');
                }
                Some('?' | '$' | '!' | '#' | '@' | '*' | '-' | '\'' | '"') => {
                    b.flag("a `$` expansion");
                    b.push('$');
                }
                _ => b.push('$'),
            },
            '#' if !b.in_word => {
                b.flag("a comment");
                b.push('#');
            }
            other => b.push(other),
        }
        i += 1;
    }
    if b.in_word || !b.words.is_empty() {
        b.end_segment();
    } else if chars.contains(&'|') && b.complex.is_none() {
        b.flag("an empty command");
    }
    b.segments.append(&mut b.nested);
    Parsed {
        segments: b.segments,
        complex: b.complex,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple(line: &str) -> Vec<Vec<String>> {
        let p = parse(line);
        assert_eq!(p.complex, None, "{line}");
        p.segments
    }

    fn complex(line: &str) -> Parsed {
        let p = parse(line);
        assert!(p.complex.is_some(), "{line} should be complex: {p:?}");
        p
    }

    #[test]
    fn words_and_quotes() {
        assert_eq!(simple("echo  a   b"), [["echo", "a", "b"]]);
        assert_eq!(simple("echo 'a b' \"c d\""), [["echo", "a b", "c d"]]);
        assert_eq!(simple(r"echo a\ b"), [["echo", "a b"]]);
        assert_eq!(simple("echo 'a'\"b\"c"), [["echo", "abc"]]);
        assert_eq!(simple("echo ''"), [["echo", ""]]);
        assert_eq!(simple(r#"echo "a\"b""#), [["echo", "a\"b"]]);
        assert_eq!(simple("echo '2^64-1' "), [["echo", "2^64-1"]]);
    }

    #[test]
    fn pipes_make_segments() {
        assert_eq!(
            simple("echo 1 | bc | wc -l"),
            [vec!["echo", "1"], vec!["bc"], vec!["wc", "-l"]]
        );
        assert_eq!(simple("echo 'a|b'"), [["echo", "a|b"]]);
        assert_eq!(simple("echo a|bc"), [vec!["echo", "a"], vec!["bc"]]);
    }

    #[test]
    fn quoted_syntax_is_plain_text() {
        for line in [
            "echo 'a; b && c > d'",
            "echo \"a; b && c > d\"",
            "echo '$HOME $(x) `y`'",
            "echo '(a) {b}'",
            "python3 -c 'print(0x9e3779b9*3 % 2**32)'",
            "echo \"cost: 5$\"",
            r"echo a\;b",
            r"echo \$HOME",
        ] {
            simple(line);
        }
    }

    #[test]
    fn each_special_form_is_complex() {
        for line in [
            "echo a; echo b",
            "echo a & echo b",
            "echo a && echo b",
            "echo a || echo b",
            "echo a > f",
            "echo a >> f",
            "cat < f",
            "cat << EOF",
            "echo a\necho b",
            "echo `id`",
            "echo $(id)",
            "echo ${HOME}",
            "echo $HOME",
            "echo $_x",
            "echo $1",
            "echo \"$HOME\"",
            "echo \"$(id)\"",
            "echo \"`id`\"",
            "(echo a)",
            "{ echo a; }",
            "echo a |& cat",
            "echo 'unclosed",
            "echo a |",
            "| echo a",
            "echo a || ",
            "echo $?",
            "echo $'x'",
            "echo a # comment",
        ] {
            complex(line);
        }
    }

    #[test]
    fn commands_after_a_separator_are_still_listed() {
        let p = complex("echo a; sudo id");
        assert_eq!(p.segments[1][0], "sudo");
        let p = complex("echo $(curl x) | bc");
        assert!(p.segments.iter().any(|s| s[0] == "curl"));
        let p = complex("echo \"$(curl x)\"");
        assert!(p.segments.iter().any(|s| s[0] == "curl"));
        let p = complex("echo `nc -l`");
        assert!(p.segments.iter().any(|s| s[0] == "nc"));
        let p = complex("(ssh x)");
        assert_eq!(p.segments, [["ssh", "x"]]);
    }

    #[test]
    fn empty_and_blank_lines() {
        assert!(parse("").segments.is_empty());
        assert!(parse("   ").segments.is_empty());
    }

    #[test]
    fn a_hash_inside_a_word_is_not_a_comment() {
        assert_eq!(simple("echo a#b"), [["echo", "a#b"]]);
    }
}
