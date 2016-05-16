#[macro_use] extern crate lazy_static;
extern crate getopts;
extern crate regex;

use std::env;
use std::io::prelude::*;
use std::io;
use std::fs::File;

use getopts::Options;

use regex::Regex;

struct LogLine {
    ip_address: String,
    identity: String,
    user: String,
    timestamp: String,
    request_line: String,
    status_code: u16,
    size: u64
}

type ParseError = &'static str;

fn parse(line: &str) -> Result<LogLine,ParseError> {
    // 127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    // 1         2               3     4                            5                             6   7
    lazy_static! {
        static ref LINE_RE: Regex = Regex::new("^(.+?) (.+?) (.+?) \\[(.+?)\\] \"(.+?)\" (.+?) (.+?)").unwrap();
    }
    
    let parts = LINE_RE.captures(line).unwrap();
    if parts.len() < 7 {
        return Err("invalid line")
    }
    
    let result = LogLine {
        ip_address: String::from(parts.at(1).unwrap()),
        identity: String::from(parts.at(2).unwrap()),
        user: String::from(parts.at(3).unwrap()),
        timestamp: String::from(parts.at(4).unwrap()),
        request_line: String::from(parts.at(5).unwrap()),
        status_code: parts[6].parse().unwrap_or(0),
        size: parts[7].parse().unwrap_or(0)
    };
    
    return Ok(result);
}

fn parse_lines<B : BufRead>(lines: io::Lines<B>) -> Vec<Result<LogLine,ParseError>> {
    lines.map(|result| {
        match result {
            Ok(s) => { parse(&s) }
            Err(_) => { Err("io error") }
        }
    }).collect()
}

fn process(file: &str) {
    match File::open(file) {
        Ok(f) => {
            let r = io::BufReader::new(f);
            let parsed_lines = parse_lines(r.lines());
            println!("parsed line count: {}", parsed_lines.len());
            for pl in parsed_lines {
                if let Ok(pl) = pl {
                    println!("{0}|{1}|{2}", pl.ip_address, pl.timestamp, pl.request_line);
                }
                
            }
        }
        Err(e) => {
            println!("Error: {}: {}", file, e);
        }
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(e) => {
            print!("{}: {}\n\n", program, e);
            return;
        }
    };

    if matches.opt_present("h") || matches.free.is_empty() {
        print_usage(&program, opts);
        return;
    }

    for file in matches.free {
        process(&file);
    }
}
