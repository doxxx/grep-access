use regex::Regex;

use AppError;
use logline::LogLine;

pub struct Grep {
    pub field: String,
    pub pattern: Regex,
}

pub fn parse_grep(s: &str) -> Result<Grep, AppError> {
    let fp = s.find(':')
        .map(|i| s.split_at(i))
        .ok_or(AppError::Parse("invalid grep option"))
        .map(|(f, p)| (f, &p[1..]));

    let grep = fp.and_then(|(field, pattern)| {
        Regex::new(&pattern)
            .map(|r| {
                Grep {
                    field: String::from(field),
                    pattern: r,
                }
            })
            .map_err(AppError::Regex)
    });

    grep
}

impl Grep {
    pub fn matches(&self, pl: &LogLine) -> bool {
        self.pattern.is_match(pl.get_field(&self.field))
    }
}
