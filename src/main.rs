use std::fs::File;
use std::fs::OpenOptions;
use std::path::PathBuf;
//use std::io::Write;

use binrw::prelude::*;
use clap::Parser;

use serde::Serialize;

#[macro_use]
extern crate lazy_static;

mod efi;

#[derive(Parser, Debug)]
#[clap(version)]
struct Args {
    /// Write modified store to <file>
    #[clap(short, long, parse(from_os_str), value_name = "file")]
    output: Option<PathBuf>,

    /// Increase verbosity
    #[clap(short, long)]
    verbose: bool,

    /// Show all variables (included deleted ones)
    #[clap(short, long)]
    all: bool,

    /// Produce debugging output
    #[clap(short, long)]
    debug: bool,

    /// De-fragment the file
    #[clap(short = 'D', long)]
    defrag: bool,

    /// JSON output
    #[clap(short, long)]
    json: bool,

    /// Scripted mode, skip headers
    #[clap(short = 'H', long)]
    scripted: bool,

    /// Select the boot entry for the next boot
    #[clap(short, long, value_name = "id")]
    bootnext: Option<u16>,

    /// Define a new boot order
    #[clap(short = 'O', long, value_name = "id[,id]...")]
    bootorder: Option<String>,

    /// Remove a variable
    #[clap(short, long, value_name = "var")]
    remove: Option<String>,

    /// List available boot options
    #[clap(short, long)]
    list: bool,

    /// Show only variables containing <substr>
    #[clap(short, long, value_name = "substr")]
    filter: Option<String>,

    /// A UEFI variable firmware volume file
    #[clap(required(true), value_name = "input", parse(from_os_str))]
    file: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();

    let path = args.file.as_deref().unwrap();
    let opath = args.output.as_deref().unwrap_or(path);

    let pd = path.display();
    let mut changed = false;

    let mut fv: efi::Volume;

    {
        let mut file = match File::open(&path) {
            Err(e) => {
                eprintln!("Could not open {}: {}", pd, e);
                std::process::exit(1)
            }
            Ok(file) => file,
        };

        fv = match file.read_le() {
            Err(e) => {
                eprintln!("Could not parse {}: {}", pd, e);
                std::process::exit(1)
            }
            Ok(v) => v,
        };
    }

    if args.debug {
        println!("{:#x?}", fv);
    }

    if fv.vars.is_empty() && !args.json {
        println!("{} is an empty variables file", pd);
        std::process::exit(0)
    }

    if args.defrag {
        fv.defrag();
        changed = true;
    }

    if let Some(ref bootorder) = args.bootorder {
        let data: Vec<u16> = bootorder
            .split(',')
            .map(|s| s.parse().expect("Error parsing boot order"))
            .collect();

        fv.set_u16_var("BootOrder", &data);
        changed = true;
    }

    if let Some(bootid) = args.bootnext {
        let data: Vec<u16> = vec![bootid];

        fv.set_u16_var("BootNext", &data);
        changed = true;
    }

    if let Some(ref var) = args.remove {
        fv.remove_var(var, &efi::EFI_GLOBAL_VARIABLE_GUID.to_string());
        changed = true;
    }

    if changed {
        let mut ofile = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&opath)
        {
            Err(e) => {
                eprintln!(
                    "Could not open output file {}: {}",
                    opath.display(),
                    e
                );
                std::process::exit(1)
            }
            Ok(file) => file,
        };

        fv.write_to(&mut ofile).expect("Could not write to output file");
    }

    if args.list {
        list_boot_options(&args, &fv);
    } else if !changed {
        display_variables(&args, &fv);
    }
}

#[derive(Debug, Serialize)]
struct BootOptions {
    order: Option<efi::BootOrder>,
    next: Option<u16>,
    entries: Vec<efi::BootEntry>,
}

fn list_boot_options(args: &Args, fv: &efi::Volume) {
    let beiter = fv.boot_entries().filter(|v| match args.filter {
        Some(ref filter) => v.name.contains(filter),
        _ => true,
    });

    let opts = BootOptions {
        order: fv.boot_order(),
        next: fv.boot_next(),
        entries: beiter.collect(),
    };

    if args.json {
        println!("{}", serde_json::to_string(&opts).unwrap());
        return;
    }

    let mut current: u16 = u16::MAX;
    let mut next: u16 = u16::MAX;

    if !args.scripted {
        println!("BOOT OPTIONS");
        println!("------------");
    }

    if let Some(bootorder) = opts.order {
        current = bootorder.first;
        if !args.scripted {
            println!("Bootorder: {:?}", bootorder.order);
        }
    }

    if let Some(n) = opts.next {
        next = n;
    }

    for be in opts.entries {
        let mut tag = String::new();
        tag.push(if be.slot == current { 'C' } else { ' ' });
        tag.push(if be.slot == next { 'N' } else { ' ' });
        tag.push(if be.attributes & efi::LOAD_OPTION_HIDDEN != 0 {
            'H'
        } else {
            ' '
        });

        let btype = match be.btype {
            efi::BootEntryType::Unknown => "".to_string(),
            ref x => format!(" - [{:?}]", x).to_string(),
        };

        println!(
            "{} [{:<2}] {}{}{}",
            tag,
            be.slot,
            be.title,
            btype,
            if be.uri { " [HTTP]" } else { "" }
        );

        if args.verbose {
            //println!("{:#x?}", be);
            if !be.pathlist.is_empty() {
                for (i, p) in be.pathlist.into_iter().enumerate() {
                    println!(
                        "    File path {:2x} Type: {:#x}/{:#x} \
                             Length: {:#x}",
                        i, p.device_type, p.sub_type, p.length
                    );
                    println!("{}", HEXDUMPER.hexdump(&p.data));
                }
            }
            if !be.optionaldata.is_empty() {
                println!("    Optional Data:");
                println!("{}", HEXDUMPER.hexdump(&be.optionaldata));
            }
            println!();
        }
    }
    if !args.scripted {
        println!("C    - Current (first in boot order)");
        println!(" N   - Next Boot");
        println!("  H  - Hidden");
    }
}

fn display_variables(args: &Args, fv: &efi::Volume) {
    let viter = (&fv.vars).iter().filter(|v| {
        if !args.all && v.state != efi::VAR_ADDED {
            false
        } else if let Some(ref filter) = args.filter {
            v.name.contains(filter)
        } else {
            true
        }
    });

    if args.json {
        let data: Vec<&efi::AuthVariable> = viter.collect();
        println!("{}", serde_json::to_string(&data).unwrap());
    } else {
        for v in viter {
            println!("{}", v);
            if args.verbose {
                print!("GUID:  {}  ", v.guid);
                println!("Date:  {}", v.timestamp);
                print!("State: {:2x}  ", v.state);
                println!("Attrs: {:x}", v.attributes);
                println!("{}\n", HEXDUMPER.hexdump(&v.data));
            }
        }
    }
}

lazy_static! {
    static ref HEXDUMPER: rhexdump::Rhexdump = {
        let mut rhx = rhexdump::Rhexdump::default();
        rhx.display_duplicate_lines(false);
        rhx
    };
}

