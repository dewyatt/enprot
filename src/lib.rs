// Copyright (c) 2018-2019 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

mod cas;
mod etree;
mod prot;

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

extern crate clap;

use clap::{App, AppSettings, Arg, ArgSettings};

// Handle command line parameters

pub fn app_main<I>(args: &mut I)
where
    I: Iterator<Item = String>,
{
    // <( ENCRYPTED AUTHOR )>
    // <( DATA X417HVMRRAs6Z1xGo5yY4TxUQ2tpAHEKQ1sg9+kfku5uUikK3y2tODtsUiGqfRGW )>
    // <( DATA xUCGYFu02BCdqPM7uuX5UNvbfrLvKkj6gLYwg/cr42PJmr4o5xnw1qo= )>
    // <( END AUTHOR )>

    let matches = App::new("enprot")
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::ColoredHelp)
        .setting(AppSettings::ColorAuto)
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Produce more verbose output"),
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .help("Suppress unnecessary output"),
        )
        .arg(
            Arg::with_name("left-separator")
                .short("l")
                .long("left-separator")
                .takes_value(true)
                .value_name("SEP")
                .help("Specify left separator in parsing"),
        )
        .arg(
            Arg::with_name("right-separator")
                .short("r")
                .long("right-separator")
                .takes_value(true)
                .value_name("SEP")
                .help("Specify right separator in parsing"),
        )
        .arg(
            Arg::with_name("store")
                .short("s")
                .long("store")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Store (unencrypted) WORD segments to CAS"),
        )
        .arg(
            Arg::with_name("fetch")
                .short("f")
                .long("fetch")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Fetch (unencrypted) WORD segments to CAS"),
        )
        .arg(
            Arg::with_name("password")
                .short("k")
                .long("key")
                .takes_value(true)
                .value_name("WORD=PASSWORD")
                .multiple(true)
                .number_of_values(1)
                .validator(|v: String| -> Result<(), String> {
                    for val in v.split(",") {
                        let wordpass = val.splitn(2, '=').collect::<Vec<&str>>();
                        if wordpass.len() != 2 || wordpass[0].len() == 0 || wordpass[1].len() == 0 {
                            return Err(String::from(
                                "Must be of the form WORD=PASSWORD[,WORD=PASSWORD]",
                            ));
                        }
                    }
                    Ok(())
                })
                .help("Specify a secret PASSWORD for WORD"),
        )
        .arg(
            Arg::with_name("encrypt")
                .short("e")
                .long("encrypt")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Encrypt WORD segments"),
        )
        .arg(
            Arg::with_name("encrypt-store")
                .short("E")
                .long("encrypt-store")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Encrypt and store WORD segments"),
        )
        .arg(
            Arg::with_name("decrypt")
                .short("d")
                .long("decrypt")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Decrypt WORD segments"),
        )
        .arg(
            Arg::with_name("casdir")
                .short("c")
                .long("casdir")
                .takes_value(true)
                .value_name("DIRECTORY")
                .default_value("./")
                .set(ArgSettings::HideDefaultValue)
                .validator(|v: String| -> Result<(), String> {
                    if Path::new(&v).is_dir() {
                        return Ok(());
                    } else {
                        Err(String::from("Must be a directory"))
                    }
                })
                .help("Directory for CAS files (default \"cas\" if exists, else \".\")"),
        )
        .arg(
            Arg::with_name("prefix")
                .short("p")
                .long("prefix")
                .takes_value(true)
                .value_name("PREFIX")
                .default_value("")
                .set(ArgSettings::HideDefaultValue)
                .set(ArgSettings::EmptyValues)
                .help("Use PREFIX for output filenames"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .takes_value(true)
                .value_name("FILE")
                .multiple(true)
                .number_of_values(1)
                .help("Specify output file for previous input"),
        )
        .arg(
            Arg::with_name("input")
                .required(true)
                .index(1)
                .value_name("FILE")
                .multiple(true)
                .help("The input file(s)"),
        )
        .get_matches_from(args);

    let mut paops = etree::ParseOps::new();
    // casdir
    if matches.occurrences_of("casdir") == 0 && Path::new("cas").is_dir() {
        paops.casdir = Path::new("cas").to_path_buf();
    } else {
        paops.casdir = Path::new(matches.value_of("casdir").unwrap()).to_path_buf();
    }
    // verbosity
    paops.verbose = matches.occurrences_of("verbose") != 0;
    if matches.occurrences_of("quiet") != 0 {
        paops.verbose = false;
    }
    // separators
    if let Some(sep) = matches.value_of("left-separator") {
        paops.left_sep = sep.to_string();
    }
    if let Some(sep) = matches.value_of("right-separator") {
        paops.right_sep = sep.to_string();
    }

    // transforms arguments like ["a", "b,c", "d"] into ["a", "b", "c", "d"]
    macro_rules! csep_arg {
        ( $set:expr, $name:expr ) => {
            $set.extend(
                matches
                    .values_of($name)
                    .unwrap_or(clap::Values::default())
                    .flat_map(|arg| arg.split(",").map(|val| val.to_string()))
                    .collect::<Vec<String>>(),
            );
        };
    }
    // expand comma-separated args
    csep_arg!(paops.store, "store");
    csep_arg!(paops.fetch, "fetch");
    csep_arg!(paops.encrypt, "encrypt");
    csep_arg!(paops.encrypt, "encrypt-store");
    csep_arg!(paops.store, "encrypt-store");
    csep_arg!(paops.decrypt, "decrypt");
    // password
    // ["word1=pass1", "word2=pass2,word3=pass3"] ->
    //   [(word1, pass1), (word2, pass2), (word3, pass3)]
    paops.passwords.extend(
        matches
            .values_of("password")
            .unwrap_or(clap::Values::default())
            .flat_map(|arg| {
                arg.split(",").map(|val| {
                    let wordpass = val.splitn(2, '=').collect::<Vec<&str>>();
                    (wordpass[0].to_string(), wordpass[1].as_bytes().to_vec())
                })
            }),
    );

    // print some of the processing parameters if verbose
    if paops.verbose {
        println!(
            "LEFT_SEP='{}' RIGHT_SEP='{}' casdir = '{}'",
            paops.left_sep,
            paops.right_sep,
            paops.casdir.display()
        );
    }

    // process all files
    let mut files = Vec::<(String, String)>::new();
    let prefix = matches.value_of("prefix").unwrap();
    let mut outiter = matches
        .values_of("output")
        .unwrap_or(clap::Values::default());
    for input in matches.values_of("input").unwrap() {
        if let Some(output) = outiter.next() {
            files.push((input.to_string(), output.to_string()));
        } else {
            files.push((input.to_string(), prefix.to_string() + &input));
        }
    }

    for (path_in, path_out) in files {
        if paops.verbose {
            println!("Reading {}", path_in);
        }

        // open input file
        let reader_in = match File::open(&path_in) {
            Ok(file_in) => BufReader::new(file_in),
            Err(e) => {
                eprintln!("Failed to open {} for reading: {}", path_in, e);
                ::std::process::exit(1);
            }
        };

        // parse input
        paops.fname = path_in.to_string();
        let tree_in = match etree::parse(reader_in, &mut paops) {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{} in {}, aborting.", e, path_in);
                ::std::process::exit(1);
            }
        };
        println!("{:#?}", tree_in);
        std::process::exit(0);

        // transform it
        if paops.verbose {
            println!("Transforming {}", path_in);
        }
        let tree_out = match etree::transform(&tree_in, &mut paops) {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{} in {}, aborting.", e, path_in);
                ::std::process::exit(1);
            }
        };

        // write it out
        if paops.verbose {
            println!("Writing {}", path_out);
        }

        // open output file
        let mut writer_out = match File::create(&path_out) {
            Ok(file_out) => BufWriter::new(file_out),
            Err(e) => {
                eprintln!("Failed to open {} for writing: {}", path_out, e);
                ::std::process::exit(1);
            }
        };

        etree::tree_write(&mut writer_out, &tree_out, &mut paops);
    }
}
