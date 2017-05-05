use regex::Regex;
use AppError;

pub struct LogLine {
    pub ip_address: String,
    pub identity: String,
    pub user: String,
    pub timestamp: String,
    pub request_line: String,
    pub status_code: String,
    pub size: String,
    pub referer: String,
    pub user_agent: String,
}

impl LogLine {
    pub fn parse(line: &str) -> Result<LogLine, AppError> {
        lazy_static! {
            static ref LINE_RE: Regex = Regex::new(
                "^(.+?) \
                (.+?) \
                (.+?) \
                \\[(.+?)\\] \
                \"(.+?)\" \
                (.+?) \
                (.+?)\
                (?: \"(.+?)\")?\
                (?: \"(.+?)\")?$"
            ).unwrap();
        }

        let parts = LINE_RE.captures(line).unwrap();
        if parts.len() < 7 {
            return Err(AppError::Parse(String::from("invalid log line")));
        }

        let result = LogLine {
            ip_address: String::from(parts.at(1).unwrap()),
            identity: String::from(parts.at(2).unwrap()),
            user: String::from(parts.at(3).unwrap()),
            timestamp: String::from(parts.at(4).unwrap()),
            request_line: String::from(parts.at(5).unwrap()),
            status_code: String::from(parts.at(6).unwrap()),
            size: String::from(parts.at(7).unwrap()),
            referer: String::from(parts.at(8).unwrap_or("")),
            user_agent: String::from(parts.at(9).unwrap_or("")),
        };

        return Ok(result);
    }

    pub fn get_field(&self, field: &str) -> &str {
        match field {
            "address" => &self.ip_address,
            "identity" => &self.identity,
            "user" => &self.user,
            "timestamp" => &self.timestamp,
            "request" => &self.request_line,
            "status" => &self.status_code,
            "size" => &self.size,
            "referer" => &self.referer,
            "user_agent" => &self.user_agent,
            _ => panic!("invalid field"),
        }
    }
}
