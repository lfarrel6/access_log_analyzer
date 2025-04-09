use super::AccessLog;
use nom::{
    IResult,
    bytes::complete::{tag, take_until},
    combinator::{map, opt},
    sequence::terminated,
};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader},
    sync::mpsc::Sender,
};

fn quote(input: &str) -> IResult<&str, &str> {
    tag("\"")(input)
}

fn space(input: &str) -> IResult<&str, &str> {
    tag(" ")(input)
}

fn match_columnar_value(val: &str) -> IResult<&str, &str> {
    let (remaining, leading_quote) = map(opt(quote), |leading_quote| leading_quote.is_some())(val)?;
    if leading_quote {
        let x = terminated(take_until(r#"""#), tag(r#"" "#))(remaining);
        return x;
    }
    let x = terminated(take_until(r#" "#), space)(remaining);
    return x;
}

pub(crate) struct LogFileBatchAnalyzer {
    // files to analyze
    batch: Vec<String>,
    // channel for passing back parsed logs
    channel: Sender<AccessLog>,
}

impl std::convert::From<(Vec<String>, Sender<AccessLog>)> for LogFileBatchAnalyzer {
    fn from((files, channel): (Vec<String>, Sender<AccessLog>)) -> Self {
        Self {
            batch: files,
            channel,
        }
    }
}

impl LogFileBatchAnalyzer {
    pub(crate) fn run(self) {
        for file_path in self.batch {
            let file_handle = OpenOptions::new().read(true).open(&file_path);

            let Ok(file_handle) = file_handle else {
                todo!("Invalid file handle");
            };
            let mut buf_reader = BufReader::new(file_handle);
            let mut access_log_line = String::with_capacity(600_usize);
            eprintln!("Processing {file_path}");
            loop {
                match buf_reader.read_line(&mut access_log_line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let mut parse_target = access_log_line.as_str();
                        let mut tokens: [&str; 30] = [std::default::Default::default(); 30];
                        let mut cnt: usize = 0;
                        loop {
                            match match_columnar_value(parse_target) {
                                _ if cnt >= tokens.len() => {
                                    eprintln!(
                                        "Encountered more fields than expected in log file, ignoring."
                                    );
                                    break;
                                }
                                Ok((x, y)) => {
                                    tokens[cnt] = y;
                                    cnt += 1;
                                    parse_target = x;
                                }
                                Err(_) => break,
                            };
                        }
                        let labelled_log = AccessLog::from(tokens);
                        if labelled_log.target_status_code.is_none() {
                            let _ = self.channel.send(labelled_log);
                        }
                        access_log_line.clear();
                    }
                    Err(_) => todo!("Handle bad file read"),
                };
            }
        }
    }
}
