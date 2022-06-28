use std::fs::File;
use std::fs::OpenOptions;
use std::path::PathBuf;
//use std::io::Write;

use binrw::prelude::*;
use clap::Parser;

#[macro_use]
extern crate lazy_static;

use rhexdump;

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
    #[clap(short='D', long)]
    defrag: bool,

    /// Select the boot entry for the next boot
    #[clap(short, long, value_name = "id")]
    bootnext: Option<u8>,

    /// List available boot options
    #[clap(short, long)]
    list: bool,

    /// Show only variables containing <substr>
    #[clap(short, long, value_name = "substr")]
    filter: Option<String>,

    /// A UEFI variable firmware volume file
    #[clap(required(true), value_name = "input",
        parse(from_os_str))]
    file: Option<PathBuf>,
}

fn main() {

    let args = Args::parse();

    let path = args.file.as_deref().unwrap();
    let opath = args.output.as_deref().unwrap_or(path.clone());

    let pd = path.display();
    let mut changed = false;

    let mut fv: efi::Volume;

    {
        let mut file = match File::open(&path) {
            Err(e) => {
                eprintln!("Could not open {}: {}", pd, e);
                std::process::exit(1)
            },
            Ok(file) => file,
        };

        fv = match file.read_le() {
            Err(e) => {
                eprintln!("Could not parse {}: {}", pd, e);
                std::process::exit(1)
            },
            Ok(v) => v,
        };
    }

    if args.debug {
        println!("{:#x?}", fv);
    }

    if fv.vars.len() == 0 {
        println!("{} is an empty variables file", pd);
        std::process::exit(0)
    }

    if args.defrag {
        fv.defrag();
        changed = true;
    }

    if let Some(bootid) = args.bootnext {
        fv.remove_var("BootNext", &efi::EFI_GLOBAL_VARIABLE_GUID.to_string());
        let bootnext = efi::AuthVariable {
            name: "BootNext".to_string(),
            namelen: 18,
            datalen: 2,
            data: vec![bootid, 0],
            ..Default::default()
        };
        if args.debug {
            println!("Adding variable: {:#x?}", bootnext);
        }
        fv.vars.push(bootnext);
        changed = true;
    }

    if changed {
        let mut ofile = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&opath) {
                Err(e) => {
                    eprintln!("Could not open output file {}: {}",
                        opath.display(), e);
                    std::process::exit(1)
                },
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

fn list_boot_options(args: &Args, fv :&efi::Volume) {
    println!("BOOT OPTIONS");
    println!("------------");
    let mut current: u16 = u16::MAX;
    let mut next: u16 = u16::MAX;

    if let Some(bootorder) = fv.boot_order() {
        current = bootorder.first;
        println!("Bootorder: {:?}", bootorder.order);
    }

    if let Some(n) = fv.boot_next() {
            next = n;
    }

    for be in fv.boot_entries() {
        if let Some(ref filter) = args.filter {
            if !be.name.contains(filter) {
                continue;
            }
        }
        let mut tag = String::new();
        tag.push(if be.slot == current { 'C' } else { ' ' });
        tag.push(if be.slot == next { 'N' } else { ' ' });
        tag.push(if be.attributes & efi::LOAD_OPTION_HIDDEN != 0
            { 'H' } else { ' ' });

        let btype = match be.btype {
            efi::BootEntryType::Unknown => "".to_string(),
            ref x => format!(" - [{:?}]", x).to_string(),
        };

        println!("{} [{:<2}] {}{}{}", tag, be.slot, be.title, btype,
            if be.uri { " [HTTP]" } else { "" });

        if args.verbose {
            //println!("{:#x?}", be);
            if be.pathlist.len() > 0 {
                for (i, p) in be.pathlist.into_iter().enumerate() {
                    println!(
                        "    File path {:2x} Type: {:#x}/{:#x} \
                             Length: {:#x}",
                        i, p.device_type, p.sub_type, p.length);
                    print!("{}\n", HEXDUMPER.hexdump(&p.data));
                }
            }
            if be.optionaldata.len() > 0 {
                println!("    Optional Data:");
                print!("{}\n", HEXDUMPER.hexdump(&be.optionaldata));
            }
            println!("");
        }
    }
    println!("C    - Current (first in boot order)");
    println!(" N   - Next Boot");
    println!("  H  - Hidden");
}

fn display_variables(args: &Args, fv: &efi::Volume) {
    // Display variables
    for v in &fv.vars {
        if args.all || v.state == efi::VAR_ADDED {
            if let Some(ref filter) = args.filter {
                if !v.name.contains(filter) {
                    continue;
                }
            }
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

