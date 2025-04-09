use serde::Serialize;
use std::fs::read_dir;

mod analyzer;

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
    target_status_code_list: Option<Box<str>>,
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
            target_status_code_list: opt_box_str_from_possible_hyphen_value(target_status_code_list),
            classification: opt_box_str_from_possible_hyphen_value(classification),
            classification_reason: opt_box_str_from_possible_hyphen_value(classification_reason),
            conn_trace_id: opt_box_str_from_empty_value(conn_trace_id),
        }
    }
}

fn main() {
    let contents = read_dir("./assets").unwrap();
    let Ok(available_parallelism) = std::thread::available_parallelism() else {
        todo!("Handle failure reading available parallelism");
    };

    let (log_of_interest_sender, log_of_interest_receiver) =
        std::sync::mpsc::channel::<AccessLog>();

    let mut log_files = contents
        .filter_map(|file| {
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

            // ignore non log files
            if !file_name.ends_with(".log") {
                return None;
            }
            let with_dir = format!("{cwd}/assets/{file_name}");
            Some(with_dir)
        })
        .collect::<Vec<String>>();

    let n_files_per_thread = log_files.len() / available_parallelism;

    for _ in 0..available_parallelism.into() {
        let files = log_files
            .drain(log_files.len() - n_files_per_thread..)
            .collect::<Vec<String>>();
        let log_sender = log_of_interest_sender.clone();
        let batch_analyzer = analyzer::LogFileBatchAnalyzer::from((files, log_sender));
        std::thread::spawn(move || {
          batch_analyzer.run();
        });
    }
    drop(log_of_interest_sender);

    let mut logs_of_interest = Vec::with_capacity(50);
    while let Ok(unhealthy_log) = log_of_interest_receiver.recv() {
      logs_of_interest.push(unhealthy_log);
    }

    if let Ok(logs) = serde_json::to_string(&logs_of_interest) {
        println!("{logs}");
    }
}
