//! A small line-based unified diff for `--dry-run`.
//!
//! Configuration files are short, so a longest-common-subsequence table over the lines
//! between the common prefix and suffix is fast enough and keeps this free of another
//! dependency. The output follows `diff -u`: `---`/`+++` headers, `@@ -a,b +c,d @@`
//! hunks with three lines of context, and `\ No newline at end of file` markers.

/// Lines of context around each change.
pub const CONTEXT: usize = 3;

/// One line of the edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// In both texts: (old index, new index).
    Same(usize, usize),
    /// Only in the old text.
    Delete(usize),
    /// Only in the new text.
    Insert(usize),
}

/// The edit script turning `old` into `new`.
fn script(old: &[&str], new: &[&str]) -> Vec<Op> {
    let prefix = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let suffix =
        old[prefix..].iter().rev().zip(new[prefix..].iter().rev()).take_while(|(a, b)| a == b).count();
    let (a, b) = (&old[prefix..old.len() - suffix], &new[prefix..new.len() - suffix]);
    // lcs[i][j]: length of the longest common subsequence of a[i..] and b[j..].
    let width = b.len() + 1;
    let mut lcs = vec![0u32; (a.len() + 1) * width];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i * width + j] = if a[i] == b[j] {
                lcs[(i + 1) * width + j + 1] + 1
            } else {
                lcs[(i + 1) * width + j].max(lcs[i * width + j + 1])
            };
        }
    }
    let mut ops: Vec<Op> = (0..prefix).map(|i| Op::Same(i, i)).collect();
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            ops.push(Op::Same(prefix + i, prefix + j));
            i += 1;
            j += 1;
        } else if j < b.len() && (i == a.len() || lcs[i * width + j + 1] >= lcs[(i + 1) * width + j]) {
            ops.push(Op::Insert(prefix + j));
            j += 1;
        } else {
            ops.push(Op::Delete(prefix + i));
            i += 1;
        }
    }
    // Deletions before insertions within a change reads better.
    let mut k = 0;
    while k < ops.len() {
        let end = ops[k..].iter().position(|op| matches!(op, Op::Same(..))).map_or(ops.len(), |n| k + n);
        ops[k..end].sort_by_key(|op| matches!(op, Op::Insert(_)));
        k = end + 1;
    }
    let (old_len, new_len) = (old.len(), new.len());
    ops.extend((0..suffix).map(|n| Op::Same(old_len - suffix + n, new_len - suffix + n)));
    ops
}

/// The range part of a hunk header: `start,len` with the conventions of `diff -u`.
fn range(start: usize, len: usize) -> String {
    match len {
        0 => format!("{start},0"),
        1 => format!("{}", start + 1),
        _ => format!("{},{len}", start + 1),
    }
}

/// Appends one diff line; a line without final newline gets the marker.
fn line(out: &mut String, mark: char, text: &str) {
    out.push(mark);
    out.push_str(text);
    if !text.ends_with('\n') {
        out.push_str("\n\\ No newline at end of file\n");
    }
}

/// The unified diff from `old` to `new`, empty if they are equal.
pub fn unified(old: &str, new: &str, old_name: &str, new_name: &str) -> String {
    let old_lines: Vec<&str> = old.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();
    let ops = script(&old_lines, &new_lines);
    let changes: Vec<usize> =
        ops.iter().enumerate().filter(|(_, op)| !matches!(op, Op::Same(..))).map(|(i, _)| i).collect();
    if changes.is_empty() {
        return String::new();
    }
    let mut out = format!("--- {old_name}\n+++ {new_name}\n");
    let mut index = 0;
    while index < changes.len() {
        // Extend the hunk while the next change is within twice the context.
        let first = changes[index];
        let mut last = first;
        while index + 1 < changes.len() && changes[index + 1] - last <= 2 * CONTEXT + 1 {
            index += 1;
            last = changes[index];
        }
        index += 1;
        let start = first.saturating_sub(CONTEXT);
        let end = (last + CONTEXT + 1).min(ops.len());
        let hunk = &ops[start..end];
        // Where the hunk starts in each text: the first line it shows, or the number of
        // lines before it.
        let old_start = ops[..start].iter().filter(|op| !matches!(op, Op::Insert(_))).count();
        let new_start = ops[..start].iter().filter(|op| !matches!(op, Op::Delete(_))).count();
        let old_len = hunk.iter().filter(|op| !matches!(op, Op::Insert(_))).count();
        let new_len = hunk.iter().filter(|op| !matches!(op, Op::Delete(_))).count();
        out.push_str(&format!("@@ -{} +{} @@\n", range(old_start, old_len), range(new_start, new_len)));
        for op in hunk {
            match *op {
                Op::Same(i, _) => line(&mut out, ' ', old_lines[i]),
                Op::Delete(i) => line(&mut out, '-', old_lines[i]),
                Op::Insert(j) => line(&mut out, '+', new_lines[j]),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diff(old: &str, new: &str) -> String {
        unified(old, new, "a", "b")
    }

    #[test]
    fn equal_texts_have_no_diff() {
        assert_eq!(diff("", ""), "");
        assert_eq!(diff("a\nb\n", "a\nb\n"), "");
    }

    #[test]
    fn addition_at_the_end() {
        assert_eq!(diff("a\nb\n", "a\nb\nc\n"), "--- a\n+++ b\n@@ -1,2 +1,3 @@\n a\n b\n+c\n");
    }

    #[test]
    fn new_and_removed_files() {
        assert_eq!(diff("", "x\ny\n"), "--- a\n+++ b\n@@ -0,0 +1,2 @@\n+x\n+y\n");
        assert_eq!(diff("x\n", ""), "--- a\n+++ b\n@@ -1 +0,0 @@\n-x\n");
    }

    #[test]
    fn change_in_the_middle_with_context() {
        let old: String = (1..=10).map(|n| format!("{n}\n")).collect();
        let new = old.replace("5\n", "five\n");
        assert_eq!(diff(&old, &new), "--- a\n+++ b\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n");
    }

    #[test]
    fn distant_changes_make_two_hunks_and_close_ones_one() {
        let old: String = (1..=20).map(|n| format!("{n}\n")).collect();
        let with = |changes: &[(usize, &str)]| -> String {
            (1..=20)
                .map(|n| {
                    changes
                        .iter()
                        .find(|(at, _)| *at == n)
                        .map_or(format!("{n}\n"), |(_, text)| format!("{text}\n"))
                })
                .collect()
        };
        let far = with(&[(2, "two"), (19, "nineteen")]);
        let text = diff(&old, &far);
        assert_eq!(text.matches("@@ ").count(), 2, "{text}");
        assert!(text.contains("@@ -1,5 +1,5 @@\n 1\n-2\n+two\n"), "{text}");
        assert!(text.contains("@@ -16,5 +16,5 @@\n 16\n 17\n 18\n-19\n+nineteen\n 20\n"), "{text}");
        let near = with(&[(5, "five"), (11, "eleven")]);
        assert_eq!(diff(&old, &near).matches("@@ ").count(), 1);
    }

    #[test]
    fn missing_final_newline_is_marked() {
        assert_eq!(
            diff("a\nb", "a\nb\n"),
            "--- a\n+++ b\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n"
        );
    }

    #[test]
    fn deletions_come_before_insertions() {
        assert_eq!(diff("a\nx\nb\n", "a\ny\nz\nb\n"), "--- a\n+++ b\n@@ -1,3 +1,4 @@\n a\n-x\n+y\n+z\n b\n");
    }

    /// Applying the diff's lines in order gives back both texts.
    #[test]
    fn script_reproduces_both_texts() {
        let old = "version = 2\n\n[agent]\nadd_to = \"a\"\n\n[profile.x]\nssh = 1\n# c\n";
        let new = "version = 2\n# top\n[agent]\nadd_to = \"b\"\n\n[profile.y]\nssh = 1\n# c\n[server.s]\n";
        let a: Vec<&str> = old.split_inclusive('\n').collect();
        let b: Vec<&str> = new.split_inclusive('\n').collect();
        let ops = script(&a, &b);
        let rebuilt_old: String = ops
            .iter()
            .filter_map(|op| match op {
                Op::Same(i, _) | Op::Delete(i) => Some(a[*i]),
                Op::Insert(_) => None,
            })
            .collect();
        let rebuilt_new: String = ops
            .iter()
            .filter_map(|op| match op {
                Op::Same(_, j) | Op::Insert(j) => Some(b[*j]),
                Op::Delete(_) => None,
            })
            .collect();
        assert_eq!(rebuilt_old, old);
        assert_eq!(rebuilt_new, new);
    }
}
