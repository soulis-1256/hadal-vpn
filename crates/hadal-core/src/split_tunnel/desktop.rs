use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopAppEntry {
    pub id: String,
    pub name: String,
    pub exec: String,
    pub bin: String,
    #[serde(default)]
    pub wm_class: Option<String>,
    pub running: bool,
}

/// Discovery source for installed desktop applications.
pub trait AppCatalog: Send + Sync {
    fn list_entries(&self) -> Vec<DesktopAppEntry>;
}

/// Production [`AppCatalog`] scanning standard XDG `.desktop` directories.
#[derive(Debug, Clone)]
pub struct XdgAppCatalog {
    dirs: Vec<PathBuf>,
}

impl XdgAppCatalog {
    pub fn system() -> Self {
        Self {
            dirs: xdg_application_dirs(),
        }
    }

    pub fn from_dirs(dirs: Vec<PathBuf>) -> Self {
        Self { dirs }
    }
}

impl Default for XdgAppCatalog {
    fn default() -> Self {
        Self::system()
    }
}

impl AppCatalog for XdgAppCatalog {
    fn list_entries(&self) -> Vec<DesktopAppEntry> {
        load_desktop_entries_from(&self.dirs)
    }
}

pub fn xdg_application_dirs() -> Vec<PathBuf> {
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(dirs::data_local_dir);
    let home = dirs::home_dir();
    let data_dirs = std::env::var("XDG_DATA_DIRS").ok();
    xdg_application_dirs_from(data_home, home, data_dirs.as_deref())
}

pub fn xdg_application_dirs_from(
    data_home: Option<PathBuf>,
    home_dir: Option<PathBuf>,
    data_dirs: Option<&str>,
) -> Vec<PathBuf> {
    let mut dirs_out = Vec::new();
    if let Some(data_home) = data_home {
        dirs_out.push(data_home.join("applications"));
        dirs_out.push(data_home.join("flatpak/exports/share/applications"));
    } else if let Some(home) = home_dir {
        dirs_out.push(home.join(".local/share/applications"));
        dirs_out.push(home.join(".local/share/flatpak/exports/share/applications"));
    }

    let raw_dirs = data_dirs.unwrap_or("/usr/local/share:/usr/share");
    for dir in raw_dirs.split(':').filter(|s| !s.trim().is_empty()) {
        dirs_out.push(PathBuf::from(dir).join("applications"));
    }
    dirs_out.push(PathBuf::from("/var/lib/flatpak/exports/share/applications"));
    dirs_out
}

pub fn load_desktop_entries_from(dirs: &[PathBuf]) -> Vec<DesktopAppEntry> {
    let mut by_id: HashMap<String, DesktopAppEntry> = HashMap::new();
    for dir in dirs {
        let Ok(read_dir) = std::fs::read_dir(dir) else {
            continue;
        };
        for item in read_dir.flatten() {
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let key = stem.to_lowercase();
            if by_id.contains_key(&key) {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Some(entry) = parse_desktop_file(stem, &content) {
                by_id.insert(key, entry);
            }
        }
    }
    by_id.into_values().collect()
}

pub fn parse_desktop_file(desktop_id: &str, content: &str) -> Option<DesktopAppEntry> {
    let mut in_main = false;
    let mut entry_type = String::new();
    let mut name = String::new();
    let mut exec_raw = String::new();
    let mut try_exec = String::new();
    let mut wm_class = None;
    let mut no_display = false;
    let mut hidden = false;

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_main = line == "[Desktop Entry]";
            continue;
        }
        if !in_main {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        match key {
            "Type" => entry_type = val.to_string(),
            "Name" if name.is_empty() => name = val.to_string(),
            "Exec" => exec_raw = val.to_string(),
            "TryExec" => try_exec = val.to_string(),
            "StartupWMClass" if !val.is_empty() => wm_class = Some(val.to_string()),
            "NoDisplay" => no_display = val.eq_ignore_ascii_case("true"),
            "Hidden" => hidden = val.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }

    if !entry_type.eq_ignore_ascii_case("Application") || no_display || hidden {
        return None;
    }
    if name.is_empty() || exec_raw.is_empty() {
        return None;
    }

    let cleaned_tokens = split_exec_tokens(&exec_raw);
    if cleaned_tokens.is_empty() {
        return None;
    }
    let exec = cleaned_tokens
        .iter()
        .map(|t| {
            if t.contains(' ') {
                format!("\"{t}\"")
            } else {
                t.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let bin = derive_primary_bin(&cleaned_tokens, &try_exec, desktop_id);
    if bin.is_empty() {
        return None;
    }

    Some(DesktopAppEntry {
        id: desktop_id.to_string(),
        name,
        exec,
        bin,
        wm_class,
        running: false,
    })
}

pub fn split_exec_tokens(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                '\\' => {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                }
                _ => cur.push(c),
            },
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }

    // Strip XDG Exec field codes (%u, %U, %f, %F, %i, %c, %k, etc.)
    tokens
        .into_iter()
        .filter(|t| !(t.starts_with('%') && t.len() == 2 && t != "%%"))
        .map(|t| if t == "%%" { "%".to_string() } else { t })
        .collect()
}

fn file_name_str(path: &str) -> Option<&str> {
    Path::new(path).file_name().and_then(|n| n.to_str())
}

pub fn derive_primary_bin(tokens: &[String], try_exec: &str, desktop_id: &str) -> String {
    let mut idx = 0usize;
    if tokens
        .first()
        .is_some_and(|s| file_name_str(s) == Some("env"))
    {
        idx += 1;
        while idx < tokens.len() && (tokens[idx].contains('=') || tokens[idx].starts_with('-')) {
            idx += 1;
        }
    }
    let first = tokens
        .get(idx)
        .or_else(|| tokens.first())
        .map(String::as_str)
        .unwrap_or("");
    let first_base = file_name_str(first).unwrap_or(first);

    if first_base == "flatpak" {
        if let Some(app_id) = tokens
            .iter()
            .skip(idx + 1)
            .find(|t| *t != "run" && !t.starts_with('-') && t.contains('.'))
        {
            return app_id.clone();
        }
    }

    if !try_exec.is_empty() {
        if let Some(base) = file_name_str(try_exec) {
            return base.to_string();
        }
    }
    if !first_base.is_empty() {
        first_base.to_string()
    } else {
        desktop_id.to_string()
    }
}

pub fn find_desktop_entry<'a>(
    entries: &'a [DesktopAppEntry],
    app: &str,
) -> Option<&'a DesktopAppEntry> {
    let needle = app.trim().to_lowercase();
    entries.iter().find(|e| {
        e.id.to_lowercase() == needle
            || e.bin.to_lowercase() == needle
            || e.name.to_lowercase() == needle
            || e.id.to_lowercase().ends_with(&format!(".{needle}"))
    })
}

fn push_unique_ci(out: &mut Vec<String>, candidate: &str) {
    let trimmed = candidate.trim();
    if !trimmed.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(trimmed)) {
        out.push(trimmed.to_string());
    }
}

pub fn aliases_for_entry(entry: &DesktopAppEntry) -> Vec<String> {
    let mut out = Vec::new();
    for cand in [
        entry.bin.as_str(),
        entry.id.as_str(),
        entry.wm_class.as_deref().unwrap_or(""),
    ] {
        push_unique_ci(&mut out, cand);
    }
    if let Some(first_tok) = split_exec_tokens(&entry.exec)
        .into_iter()
        .find(|t| !t.contains('=') && t != "env")
    {
        if let Some(base) = file_name_str(&first_tok) {
            if base != "flatpak" {
                push_unique_ci(&mut out, base);
            }
        }
    }
    for extra in app_aliases(&entry.bin) {
        push_unique_ci(&mut out, &extra);
    }
    out
}

pub fn resolve_aliases_with_entries(app: &str, entries: &[DesktopAppEntry]) -> Vec<String> {
    let mut aliases = app_aliases(app);
    if let Some(entry) = find_desktop_entry(entries, app) {
        for alias in aliases_for_entry(entry) {
            push_unique_ci(&mut aliases, &alias);
        }
    }
    aliases
}

pub fn app_aliases(app: &str) -> Vec<String> {
    match app.trim().to_lowercase().as_str() {
        "brave" | "brave-browser" => vec![
            "brave".into(),
            "brave-browser".into(),
            "brave-browser-stable".into(),
            "brave-bin".into(),
            "/opt/brave.com/brave/brave".into(),
        ],
        "zen" | "zen-browser" | "app.zen_browser.zen" => vec![
            "zen".into(),
            "zen-bin".into(),
            "zen-browser".into(),
            "/opt/zen-browser-bin/zen-bin".into(),
        ],
        "steam" => vec!["steam".into(), "steamwebhelper".into()],
        "discord" => vec!["discord".into(), "Discord".into()],
        "spotify" => vec!["spotify".into()],
        "qbittorrent" => vec!["qbittorrent".into(), "qbittorrent-nox".into()],
        "firefox" => vec!["firefox".into(), "firefox-bin".into()],
        other => vec![other.to_string()],
    }
}
