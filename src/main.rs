use nom::{
    IResult,
    bytes::complete::{tag, take_until},
    combinator::{map, opt},
    sequence::terminated,
};
use serde::Serialize;
use std::fs::{OpenOptions, read_dir};
use std::io::{BufRead, BufReader};

#[derive(Default, Serialize)]
struct AccessLog {
    log_type: Box<str>,
    time: Box<str>,
    elb: Box<str>,
    client_addr: Box<str>,
    target_addr: Box<str>,
    request_processing_time: Box<str>,
    target_processing_time: Option<Box<str>>,
    response_processing_time: Option<Box<str>>,
    elb_status_code: Box<str>,
    target_status_code: Option<Box<str>>,
    received_bytes: Box<str>,
    sent_bytes: Box<str>,
    request_line: Box<str>,
    user_agent: Box<str>,
    ssl_cipher: Box<str>,
    ssl_protocol: Box<str>,
    target_group_arn: Box<str>,
    trace_id: Box<str>,
    domain_name: Box<str>,
    chosen_cert_arn: Box<str>,
    matched_rule_priority: Box<str>,
    request_creation_time: Box<str>,
    actions_executed: Box<str>,
    redirect_url: Option<Box<str>>,
    error_reason: Option<Box<str>>,
    target_port_list: Box<str>,
    target_status_code_list: Box<str>,
    classification: Option<Box<str>>,
    classification_reason: Option<Box<str>>,
    conn_trace_id: Option<Box<str>>,
}

fn opt_box_str_from_possible_hyphen_value(val: &str) -> Option<Box<str>> {
    match val {
        "-" => None,
        val => Some(val.into()),
    }
}

fn opt_box_str_from_negative_value(val: &str) -> Option<Box<str>> {
    match val {
        "-1" => None,
        val => Some(val.into()),
    }
}

fn opt_box_str_from_empty_value(val: &str) -> Option<Box<str>> {
    match val {
        "" => None,
        val => Some(val.into()),
    }
}

impl std::convert::From<[&str; 30]> for AccessLog {
    fn from(value: [&str; 30]) -> Self {
        let [
            log_type,
            time,
            elb,
            client_addr,
            target_addr,
            request_processing_time,
            target_processing_time,
            response_processing_time,
            elb_status_code,
            target_status_code,
            received_bytes,
            sent_bytes,
            request_line,
            user_agent,
            ssl_cipher,
            ssl_protocol,
            target_group_arn,
            trace_id,
            domain_name,
            chosen_cert_arn,
            matched_rule_priority,
            request_creation_time,
            actions_executed,
            redirect_url,
            error_reason,
            target_port_list,
            target_status_code_list,
            classification,
            classification_reason,
            conn_trace_id,
        ] = value;

        Self {
            log_type: log_type.into(),
            time: time.into(),
            elb: elb.into(),
            client_addr: client_addr.into(),
            target_addr: target_addr.into(),
            request_processing_time: request_processing_time.into(),
            target_processing_time: opt_box_str_from_negative_value(target_processing_time),
            response_processing_time: opt_box_str_from_negative_value(response_processing_time),
            elb_status_code: elb_status_code.into(),
            target_status_code: opt_box_str_from_possible_hyphen_value(target_status_code),
            received_bytes: received_bytes.into(),
            sent_bytes: sent_bytes.into(),
            request_line: request_line.into(),
            user_agent: user_agent.into(),
            ssl_cipher: ssl_cipher.into(),
            ssl_protocol: ssl_protocol.into(),
            target_group_arn: target_group_arn.into(),
            trace_id: trace_id.into(),
            domain_name: domain_name.into(),
            chosen_cert_arn: chosen_cert_arn.into(),
            matched_rule_priority: matched_rule_priority.into(),
            request_creation_time: request_creation_time.into(),
            actions_executed: actions_executed.into(),
            redirect_url: opt_box_str_from_possible_hyphen_value(redirect_url),
            error_reason: opt_box_str_from_possible_hyphen_value(error_reason),
            target_port_list: target_port_list.into(),
            target_status_code_list: target_status_code_list.into(),
            classification: opt_box_str_from_possible_hyphen_value(classification),
            classification_reason: opt_box_str_from_possible_hyphen_value(classification_reason),
            conn_trace_id: opt_box_str_from_empty_value(conn_trace_id),
        }
    }
}

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

fn main() {
    let contents = read_dir("./assets").unwrap();
    let mut parsed_logs = vec![];

    contents.for_each(|file| {
        let Ok(file) = file else {
            todo!("Handle error in dir entries");
        };
        let Ok(Ok(cwd)) = std::env::current_dir().map(|cwd| cwd.into_os_string().into_string())
        else {
            todo!("No CWD available");
        };
        let Ok(file_name) = file.file_name().into_string() else {
            todo!("Unserializable file name");
        };
        let with_dir = format!("{cwd}/assets/{file_name}");
        let file_handle = OpenOptions::new().read(true).open(&with_dir);

        let Ok(file_handle) = file_handle else {
            todo!("Invalid file handle");
        };
        let mut buf_reader = BufReader::new(file_handle);
        let mut access_log_line = String::with_capacity(600_usize);
        loop {
            match buf_reader.read_line(&mut access_log_line) {
                Ok(0) => break,
                Ok(_) => {
                    let mut parse_target = access_log_line.as_str();
                    let mut tokens: [&str; 30] = [std::default::Default::default(); 30];
                    let mut cnt: usize = 0;
                    loop {
                        match match_columnar_value(parse_target) {
                            Ok((x, y)) => {
                                tokens[cnt] = y;
                                cnt += 1;
                                parse_target = x;
                            }
                            Err(_) => break,
                        };
                    }
                    parsed_logs.push(AccessLog::from(tokens));
                    access_log_line.clear();
                }
                Err(_) => todo!("Handle bad file read"),
            };
        }
    });
    let Ok(parsed_logs) = serde_json::to_string(&parsed_logs) else {
        todo!("Handle invalid log")
    };
    println!("{parsed_logs}");
}
