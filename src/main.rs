#[macro_use] extern crate lazy_static;
extern crate getopts;
extern crate regex;

use std::env;
use std::io::prelude::*;
use std::io;
use std::fs::File;
use std::fmt;

use getopts::Options;
use getopts::HasArg;
use getopts::Occur;

use regex::Regex;

struct LogLine {
    ip_address: String,
    identity: String,
    user: String,
    timestamp: String,
    request_line: String,
    status_code: u16,
    size: u64,
    referer: String,
    user_agent: String
}

struct Grep {
    field: String,
    pattern: Regex
}

fn parse_grep(s: &str) -> Result<Grep,ParseError> {
    let fp = s.find(':')
     .map(|i| s.split_at(i))
     .ok_or("invalid grep option")
     .map(|(f,p)| (f,&p[1..]));
    
    let grep = fp.and_then(|(field, pattern)| {
         Regex::new(&pattern).map(|r| {
             Grep {
                 field: String::from(field),
                 pattern: r
             }
         })
         .map_err(|e| "Invalid grep option")
     });
     
     grep
}

impl Grep {
    fn matches(&self, pl: &LogLine) -> bool {
        match self.field.as_str() {
            "address" => self.pattern.is_match(pl.ip_address.as_str()),
            "identity" => self.pattern.is_match(pl.identity.as_str()),
            "user" => self.pattern.is_match(pl.user.as_str()),
            "timestamp" => self.pattern.is_match(pl.timestamp.as_str()),
            "request" => self.pattern.is_match(pl.request_line.as_str()),
            "status" => self.pattern.is_match(fmt::format(format_args!("{}", pl.status_code)).as_str()),
            "size" => self.pattern.is_match(fmt::format(format_args!("{}", pl.size)).as_str()),
            "referer" => self.pattern.is_match(pl.referer.as_str()),
            "user_agent" => self.pattern.is_match(pl.user_agent.as_str()),
            _ => panic!("unrecognized grep field")
        }
    }
}

type ParseError = &'static str;

fn parse_line(line: &str) -> Result<LogLine,ParseError> {
    // 127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "referer" "user-agent"
    // 1         2               3     4                            5                             6   7    8          9
    lazy_static! {
        static ref LINE_RE: Regex = Regex::new("^(.+?) (.+?) (.+?) \\[(.+?)\\] \"(.+?)\" (.+?) (.+?)(?: \"(.+?)\")?(?: \"(.+?)\")?$").unwrap();
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
        size: parts[7].parse().unwrap_or(0),
        referer: String::from(parts.at(8).unwrap_or("")),
        user_agent: String::from(parts.at(9).unwrap_or("")),
    };
    
    return Ok(result);
}

fn process(fields: &Vec<String>, delimiter: &str, greps: &Vec<Grep>, quote: &str, file: &str) {
    match File::open(file) {
        Ok(f) => {
            let r = io::BufReader::new(f);
            for line in r.lines() {
                if let Ok(s) = line {
                    let parse_result = parse_line(&s);
                    if let Ok(pl) = parse_result {
                        let grep_matches = greps.iter().all(|g| g.matches(&pl));
                        if greps.is_empty() || grep_matches {
                            for field in fields {
                                match field.as_str() {
                                    "address" => print!("{1}{0}{1}", pl.ip_address, quote),
                                    "identity" => print!("{1}{0}{1}", pl.identity, quote),
                                    "user" => print!("{1}{0}{1}", pl.user, quote),
                                    "timestamp" => print!("{1}{0}{1}", pl.timestamp, quote),
                                    "request" => print!("{1}{0}{1}", pl.request_line, quote),
                                    "status" => print!("{1}{0}{1}", pl.status_code, quote),
                                    "size" => print!("{1}{0}{1}", pl.size, quote),
                                    "referer" => print!("{1}{0}{1}", pl.referer, quote),
                                    "user_agent" => print!("{1}{0}{1}", pl.user_agent, quote),
                                    _ => {}
                                }
                                print!("{}", delimiter);
                            }
                            println!("");
                        }
                    }
                }
            }
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
    opts.opt("f", "fields", "comma-separated list of fields to display: address, identity, user, timestamp, request, status, size, referer, user_agent; defaults to all", "<FIELDS>", HasArg::Yes, Occur::Optional);
    opts.opt("d", "delimiter", "delimiter used to separate fields; defaults to '|'", "<DELIMITER>", HasArg::Yes, Occur::Optional);
    opts.opt("q", "quote", "quote fields; defaults to not quoting", "<QUOTECHAR>", HasArg::Yes, Occur::Optional);
    opts.opt("g", "grep", "outputs only those lines which match the given regex for the given field; multiple options are AND'ed together'", "<FIELD:REGEX>", HasArg::Yes, Occur::Multi);
    
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
    
    let default_fields = String::from("address,identity,user,timestamp,request,status,size,referer,user_agent");
    let default_delimiter = String::from("|");
    let default_quote = String::from("");
    
    let fields: Vec<String> = matches.opt_str("f").unwrap_or(default_fields).split(',').map(|s| String::from(s)).collect();
    let delimiter: String = matches.opt_str("d").unwrap_or(default_delimiter);
    let greps: Vec<Result<Grep,ParseError>> = matches.opt_strs("g").iter().map(|s| parse_grep(&s)).collect();
    let quote: String = matches.opt_str("q").unwrap_or(default_quote);
    
    if greps.iter().any(|g| g.is_err()) {
        println!("{}: invalid grep option", program);
        return;
    }
    
    let greps: Vec<Grep> = greps.into_iter().map(|r| r.unwrap()).collect();
    
    for file in matches.free {
        process(&fields, &delimiter, &greps, &quote, &file);
    }
}
