#[macro_use] extern crate lazy_static;
extern crate getopts;
extern crate regex;

use std::env;
use std::io::prelude::*;
use std::io;
use std::fs::File;

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
    size: u64
}

type ParseError = &'static str;

fn parse_line(line: &str) -> Result<LogLine,ParseError> {
    // 127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    // 1         2               3     4                            5                             6   7
    lazy_static! {
        static ref LINE_RE: Regex = Regex::new("^(.+?) (.+?) (.+?) \\[(.+?)\\] \"(.+?)\" (.+?) (.+?)( |$)").unwrap();
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

fn process(fields: &Vec<String>, delimiter: &str, file: &str) {
    match File::open(file) {
        Ok(f) => {
            let r = io::BufReader::new(f);
            for line in r.lines() {
                if let Ok(s) = line {
                    let parse_result = parse_line(&s);
                    if let Ok(pl) = parse_result {
                        for field in fields {
                            match field.as_str() {
                                "address" => print!("{0}", pl.ip_address),
                                "identity" => print!("{0}", pl.identity),
                                "user" => print!("{0}", pl.user),
                                "timestamp" => print!("{0}", pl.timestamp),
                                "request" => print!("{0}", pl.request_line),
                                "status" => print!("{0}", pl.status_code),
                                "size" => print!("{0}", pl.size),
                                _ => {}
                            }
                            print!("{}", delimiter);
                        }
                        println!("");
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
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.opt("f", "filter", "comma-separated list of fields to display: address, identity, user, timestamp, request, status, size", "<FIELDS>", HasArg::Yes, Occur::Optional);
    opts.opt("d", "delimiter", "delimiter used to separate fields", "<DELIMITER>", HasArg::Yes, Occur::Optional);
    
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
    
    let default_fields = String::from("address,identity,user,timestamp,request,status,size");
    let default_delimiter = String::from("|");
    
    let fields: Vec<String> = matches.opt_str("f").unwrap_or(default_fields)
            .split(',').map(|s| String::from(s)).collect();
    let delimiter: String = matches.opt_str("d").unwrap_or(default_delimiter);

    for file in matches.free {
        process(&fields, &delimiter, &file);
    }
}
