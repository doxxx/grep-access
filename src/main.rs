// Modules in this crate
mod logline;
mod grep;

#[macro_use]
extern crate lazy_static;
extern crate getopts;
extern crate regex;

use std::env;
use std::io::prelude::*;
use std::io;
use std::fs::File;

use getopts::Options;
use getopts::HasArg;
use getopts::Occur;

use logline::LogLine;
use logline::parse_line;
use logline::ParseError;
use grep::Grep;
use grep::parse_grep;

fn quoted_field(pl: &LogLine, field: &str, quote: &str) -> String {
    String::from(pl.get_field(field)
        .map(|v| format!("{1}{0}{1}", v, quote))
        .expect("invalid field"))
}

fn join_fields(fields: &[String], delimiter: &str, quote: &str, pl: LogLine) -> String {
    fields.iter().fold(String::new(), |acc, field| {
        if acc.len() > 0 {
            acc + delimiter + quoted_field(&pl, field, quote).as_str()
        } else {
            quoted_field(&pl, field, quote)
        }
    })
}

fn process_line(fields: &[String], delimiter: &str, greps: &[Grep], quote: &str, pl: LogLine) {
    let grep_matches = greps.iter().all(|g| g.matches(&pl));
    if greps.is_empty() || grep_matches {
        let output_line = join_fields(fields, delimiter, quote, pl);
        println!("{0}", output_line);
    }
}

fn process_lines<B>(fields: &[String],
                    delimiter: &str,
                    greps: &[Grep],
                    quote: &str,
                    lines: io::Lines<B>)
    where B: BufRead + Sized
{
    for line in lines {
        if let Ok(s) = line {
            let parse_result = parse_line(&s);
            if let Ok(pl) = parse_result {
                process_line(fields, delimiter, greps, quote, pl)
            }
        }
    }
}

fn process_file(fields: &[String], delimiter: &str, greps: &[Grep], quote: &str, file: &str) {
    match File::open(file) {
        Ok(f) => {
            let r = io::BufReader::new(f);
            process_lines(fields, delimiter, greps, quote, r.lines());
        }
        Err(e) => {
            println!("Error: {}: {}", file, e);
        }
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] <file> [<file>...]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.opt("f",
             "fields",
             "comma-separated list of fields to display: address, identity, user, timestamp, \
              request, status, size, referer, user_agent; defaults to all",
             "<FIELDS>",
             HasArg::Yes,
             Occur::Optional);
    opts.opt("d",
             "delimiter",
             "delimiter used to separate fields; defaults to '|'",
             "<DELIMITER>",
             HasArg::Yes,
             Occur::Optional);
    opts.opt("q",
             "quote",
             "quote fields; defaults to not quoting",
             "<QUOTECHAR>",
             HasArg::Yes,
             Occur::Optional);
    opts.opt("g",
             "grep",
             "outputs only those lines which match the given regex for the given field; multiple \
              options are AND'ed together'",
             "<FIELD:REGEX>",
             HasArg::Yes,
             Occur::Multi);

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            print!("{}: {}\n\n", program, e);
            return;
        }
    };

    if matches.opt_present("h") || matches.free.is_empty() {
        print_usage(&program, opts);
        return;
    }

    let default_fields = String::from("address,identity,user,timestamp,request,status,size,\
                                       referer,user_agent");
    let default_delimiter = String::from("|");
    let default_quote = String::from("");

    let fields: Vec<String> = matches.opt_str("f")
        .unwrap_or(default_fields)
        .split(',')
        .map(|s| String::from(s))
        .collect();
    let delimiter: String = matches.opt_str("d").unwrap_or(default_delimiter);
    let greps: Vec<Result<Grep, ParseError>> =
        matches.opt_strs("g").iter().map(|s| parse_grep(&s)).collect();
    let quote: String = matches.opt_str("q").unwrap_or(default_quote);

    if greps.iter().any(|g| g.is_err()) {
        println!("{}: invalid grep option", program);
        return;
    }

    let greps: Vec<Grep> = greps.into_iter().map(|r| r.unwrap()).collect();

    for file in matches.free {
        process_file(&fields, &delimiter, &greps, &quote, &file);
    }
}
