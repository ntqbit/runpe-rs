use std::ffi::CString;

use clap::{arg, value_parser, ArgAction, Command};
use runpe::{Argument, Payload};

#[derive(Debug, Clone, clap::ValueEnum)]
enum PayloadType {
    Shell,
    Pe,
}

fn cli() -> Command {
    Command::new("runpe")
        .arg(arg!(-e --executable <executable> "Executable path").required(true))
        .arg(arg!(-r --resume <resume> "Resume process").action(ArgAction::SetTrue))
        .arg(arg!(-f --file <file> "Payload file").required(true))
        .arg(
            arg!(-t --type <type> "Payload type")
                .required(true)
                .value_parser(value_parser!(PayloadType)),
        )
        .arg(arg!(-a --argument <argument> "Argument"))
}

fn main() -> anyhow::Result<()> {
    let cmd = cli();
    let matches = cmd.get_matches();

    let executable = matches.get_one::<String>("executable").unwrap().clone();
    let resume = *matches.get_one::<bool>("resume").unwrap();
    let file = matches.get_one::<String>("file").unwrap().clone();
    let payload_type = matches.get_one::<PayloadType>("type").unwrap().clone();
    let argument_cloned = matches
        .get_one::<String>("argument")
        .map(|x| x.clone().into_bytes());

    let argument = match &argument_cloned {
        Some(a) => Argument::Bytes(a),
        None => Argument::None,
    };

    let file_data = std::fs::read(file)?;

    let executable = CString::new(executable).unwrap();
    let payload = match payload_type {
        PayloadType::Shell => Payload::Shellcode(&file_data),
        PayloadType::Pe => Payload::Pe(&file_data),
    };

    let result = unsafe { runpe::runpe(executable.as_ptr(), payload, resume, argument) };

    match result {
        Ok(pi) => println!("Success. PID: {:?}", pi.dwProcessId),
        Err(err) => eprintln!("Error: {:?}", err),
    }

    Ok(())
}
