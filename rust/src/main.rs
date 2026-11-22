use keylens::{scan_path, to_json, VERSION};
use std::process;

fn usage() {
    eprintln!(
        "keylens — поиск утекших API-ключей и токенов\n\n\
Использование:\n  keylens scan [путь] [--json] [--exclude DIR] [--max-size MB] [--quiet]\n\n\
Флаги:\n  --json              вывод в формате JSON\n  --exclude DIR       исключить каталог (можно повторять)\n  --max-size MB       максимальный размер файла (по умолчанию 2)\n  --quiet             только код возврата\n  --version           версия"
    );
}

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return 2;
    }
    if args[0] == "--version" || args[0] == "-v" {
        println!("keylens {}", VERSION);
        return 0;
    }
    if args[0] != "scan" {
        usage();
        return 2;
    }

    let mut path = ".".to_string();
    let mut json_out = false;
    let mut quiet = false;
    let mut excludes: Vec<String> = Vec::new();
    let mut max_mb: u64 = 2;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_out = true,
            "--quiet" => quiet = true,
            "-h" | "--help" => {
                usage();
                return 0;
            }
            "--exclude" => {
                if i + 1 >= args.len() {
                    usage();
                    return 2;
                }
                i += 1;
                excludes.push(args[i].clone());
            }
            "--max-size" => {
                if i + 1 >= args.len() {
                    usage();
                    return 2;
                }
                i += 1;
                match args[i].parse::<u64>() {
                    Ok(n) => max_mb = n,
                    Err(_) => {
                        eprintln!("keylens: неверный --max-size");
                        return 2;
                    }
                }
            }
            arg if arg.starts_with('-') || path != "." => {
                usage();
                return 2;
            }
            arg => path = arg.to_string(),
        }
        i += 1;
    }

    if !std::path::Path::new(&path).exists() {
        eprintln!("keylens: путь не найден: {}", path);
        return 2;
    }

    let (findings, scanned) = match scan_path(&path, &excludes, max_mb * 1024 * 1024) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("keylens: {}", e);
            return 2;
        }
    };

    if json_out {
        println!("{}", to_json(&findings));
    } else if !quiet {
        println!("🔍 keylens: просмотрено файлов: {}", scanned);
        if !findings.is_empty() {
            println!(
                "⚠️  Найдено потенциальных секретов: {}\n",
                findings.len()
            );
            for f in &findings {
                println!(
                    "  [{}] {:28} {}:{} — {}",
                    f.severity, f.matched, f.file, f.line, f.pattern
                );
            }
        } else {
            println!("✅ Секретов не найдено");
        }
    }

    if findings.is_empty() {
        0
    } else {
        1
    }
}
