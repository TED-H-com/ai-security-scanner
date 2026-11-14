use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() && (c as u32) <= 0xff => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn array(args: &[String]) -> String {
    format!(
        "[{}]",
        args.iter()
            .map(|s| json_string(s))
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn hex64(s: &str) -> String {
    (0u64..4)
        .map(|i| {
            let mut h = 0xcbf29ce484222325u64 ^ i.wrapping_mul(0x9e3779b97f4a7c15);
            for b in s.bytes() {
                h = (h ^ u64::from(b)).wrapping_mul(0x100000001b3);
            }
            format!("{h:016x}")
        })
        .collect()
}
fn run() -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let root = exe.parent().ok_or("current_exe parent missing")?;
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls.jsonl"))
        .and_then(|mut f| f.write_all(format!("{}\n", array(&args)).as_bytes()))
        .map_err(|e| format!("append calls: {e}"))?;
    let read = |p: &Path| fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()));
    let write =
        |p: &Path, s: &str| fs::write(p, s).map_err(|e| format!("write {}: {e}", p.display()));
    let personality = read(&root.join("personality"))?;
    let personality = personality.trim();
    let mode = read(&root.join("mode"))?;
    let mode = mode.trim();
    let foreground = personality == "foreground";
    if !foreground && personality != "preparation" {
        return Err("unknown personality".into());
    }
    if mode == "deny" {
        eprintln!(
            "{}",
            if foreground {
                "fixture forbids every runtime operation"
            } else {
                "fixture refuses runtime contact"
            }
        );
        return Ok(91);
    }
    let op = args.first().ok_or("missing operation")?.as_str();
    let last = || {
        args.last()
            .map(String::as_str)
            .ok_or_else(|| "missing last argument".to_string())
    };
    let version = if foreground {
        "99.0.0-offline-fixture"
    } else {
        "99.0.0-preparation-fixture"
    };
    let security = "[\"name=seccomp,profile=builtin\",\"name=rootless\"]";
    let atomic = |name: &str, content: &str| -> Result<(), String> {
        let tmp = root.join(format!("{name}.{}.tmp", std::process::id()));
        write(&tmp, content)?;
        fs::rename(&tmp, root.join(name)).map_err(|e| format!("rename {name}: {e}"))
    };
    let wait = |seconds, stopped: Option<&Path>| -> Result<i32, String> {
        let start = Instant::now();
        while !root.join("release").exists() && !stopped.is_some_and(Path::exists) {
            if start.elapsed() > Duration::from_secs(seconds) {
                eprintln!("fixture watchdog expired");
                return Ok(92);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(0)
    };
    match op {
        "version" => println!("{version}"),
        "info" => {
            if last()?.contains("serverVersion") {
                println!(
                    "{{\"serverVersion\":{},\"securityOptions\":{security}}}",
                    json_string(version)
                );
            } else {
                println!("{security}");
            }
        }
        "image" if args.get(1).is_some_and(|s| s == "inspect") => {
            if foreground {
                println!("[]");
            } else {
                if args.len() < 3 {
                    return Err("missing image inspect image".into());
                }
                let image = last()?;
                if mode == "block" || (mode == "block-nuclei" && image.contains("engine-nuclei@")) {
                    atomic(
                        "blocked.json",
                        &format!(
                            "{{\"pid\":{},\"image\":{}}}",
                            std::process::id(),
                            json_string(image)
                        ),
                    )?;
                    let code = wait(12, None)?;
                    if code != 0 {
                        return Ok(code);
                    }
                }
                let id = hex64(image);
                if (mode == "missing" || mode == "mixed") && !root.join(&id).exists() {
                    eprintln!("No such image");
                    return Ok(1);
                }
                println!(
                    "[{{\"Id\":{},\"RepoDigests\":[{}]}}]",
                    json_string(&format!("sha256:{id}")),
                    json_string(image)
                );
            }
        }
        "pull" if !foreground => {
            if args.len() < 2 {
                return Err("missing pull image".into());
            }
            let image = last()?;
            if !image.contains("@sha256:") {
                eprintln!("fixture refuses unpinned pull");
                return Ok(93);
            }
            if mode == "mixed" && image.contains("engine-gitleaks@") {
                eprintln!("synthetic registry failure");
                return Ok(9);
            }
            write(&root.join(hex64(image)), "present")?;
            println!("pinned image retrieved");
        }
        "run" if foreground => {
            let option = |key: &str| -> Result<&str, String> {
                let i = args
                    .iter()
                    .position(|s| s == key)
                    .ok_or_else(|| format!("missing {key}"))?;
                args.get(i + 1)
                    .map(String::as_str)
                    .ok_or_else(|| format!("missing value for {key}"))
            };
            let mut labels = BTreeMap::new();
            let mut output = None;
            for (i, arg) in args.iter().enumerate() {
                if arg == "--label" {
                    let value = args.get(i + 1).ok_or("missing label")?;
                    let (k, v) = value.split_once('=').ok_or("invalid label")?;
                    labels.insert(k, v);
                }
                if arg == "--mount" {
                    let value = args.get(i + 1).ok_or("missing mount")?;
                    let parts: BTreeMap<_, _> =
                        value.split(',').filter_map(|p| p.split_once('=')).collect();
                    if parts
                        .get("dst")
                        .or_else(|| parts.get("target"))
                        .or_else(|| parts.get("destination"))
                        == Some(&"/output")
                    {
                        output = parts.get("src").or_else(|| parts.get("source")).copied();
                    }
                }
            }
            let output = output.ok_or("missing output mount")?;
            let name = option("--name")?;
            let id = hex64(name);
            let image = args
                .iter()
                .find(|s| s.contains("@sha256:"))
                .ok_or("missing image")?;
            let labels_json = labels
                .iter()
                .map(|(k, v)| format!("{}:{}", json_string(k), json_string(v)))
                .collect::<Vec<_>>()
                .join(",");
            write(
                &root.join(format!("{id}.json")),
                &format!(
                    "{{\"Id\":{},\"Name\":{},\"Config\":{{\"Image\":{},\"Labels\":{{{labels_json}}}}}}}",
                    json_string(&id),
                    json_string(name),
                    json_string(image)
                ),
            )?;
            write(&root.join(format!("{id}.name")), name)?;
            write(Path::new(option("--cidfile")?), &format!("{id}\n"))?;
            atomic(
                "running.json",
                &format!(
                    "{{\"pid\":{},\"id\":{},\"name\":{}}}",
                    std::process::id(),
                    json_string(&id),
                    json_string(name)
                ),
            )?;
            if mode == "block" {
                let code = wait(20, Some(&root.join(format!("{id}.stopped"))))?;
                if code != 0 {
                    return Ok(code);
                }
            }
            if labels.get("ai.security-scanner.engine") == Some(&"semgrep") {
                eprintln!("synthetic scanner failure");
                return Ok(9);
            }
            let data =
                fs::read(root.join("gitleaks.json")).map_err(|e| format!("read gitleaks: {e}"))?;
            fs::write(Path::new(output).join("gitleaks.json"), data)
                .map_err(|e| format!("write gitleaks: {e}"))?;
            println!("offline fixture output captured");
        }
        "container" if foreground && args.get(1).is_some_and(|s| s == "inspect") => {
            if args.len() < 3 {
                return Err("missing container inspect query".into());
            }
            let query = last()?;
            let mut selected = Vec::new();
            for entry in fs::read_dir(root).map_err(|e| format!("read directory: {e}"))? {
                let path = entry.map_err(|e| format!("read entry: {e}"))?.path();
                if path.extension().is_some_and(|x| x == "json")
                    && let Some(stem) = path.file_stem().and_then(|x| x.to_str())
                    && stem.len() == 64
                    && (stem == query || read(&root.join(format!("{stem}.name")))? == query)
                {
                    selected.push(path);
                }
            }
            if selected.len() != 1 {
                eprintln!("No such container");
                return Ok(1);
            }
            println!("[{}]", read(&selected[0])?);
        }
        "stop" | "rm" if foreground => {
            if args.len() < 2 {
                return Err("missing container identity".into());
            }
            let id = last()?;
            if id.len() != 64 {
                eprintln!("fixture refuses control by mutable name");
                return Ok(93);
            }
            write(&root.join(format!("{id}.stopped")), "stopped")?;
            if op == "rm" {
                for ext in ["json", "name"] {
                    match fs::remove_file(root.join(format!("{id}.{ext}"))) {
                        Ok(()) => (),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => return Err(format!("remove state: {e}")),
                    }
                }
            }
        }
        _ => {
            eprintln!(
                "{}: {}",
                if foreground {
                    "unexpected fixture runtime operation"
                } else {
                    "preparation must not create containers or networks"
                },
                array(&args)
            );
            return Ok(94);
        }
    }
    Ok(0)
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("fixture error: {e}");
            std::process::exit(95);
        }
    }
}
