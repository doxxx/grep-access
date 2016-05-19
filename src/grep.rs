use regex::Regex;

use logline::LogLine;
use logline::ParseError;

pub struct Grep {
    pub field: String,
    pub pattern: Regex,
}

pub fn parse_grep(s: &str) -> Result<Grep, ParseError> {
    let fp = s.find(':')
        .map(|i| s.split_at(i))
        .ok_or("invalid grep option")
        .map(|(f, p)| (f, &p[1..]));

    let grep = fp.and_then(|(field, pattern)| {
        Regex::new(&pattern)
            .map(|r| {
                Grep {
                    field: String::from(field),
                    pattern: r,
                }
            })
            .map_err(|e| "Invalid grep option")
    });

    grep
}

impl Grep {
    pub fn matches(&self, pl: &LogLine) -> bool {
        pl.get_field(&self.field).map(|v| self.pattern.is_match(v)).expect("invalid grep field")
    }
}

