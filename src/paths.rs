use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

const MAX_COMPONENT_BYTES: usize = 255;
const MAX_PASS_PATH_BYTES: usize = 4096;

pub fn validate_component(value: &str) -> Result<()> {
    if value.is_empty() || value == "." || value == ".." {
        bail!("path component is empty or reserved");
    }
    let lowercase = value.to_ascii_lowercase();
    if lowercase == ".git" || lowercase.starts_with(".proton-pass-sync-stage-") {
        bail!("path component uses an internally reserved name");
    }
    if value.len() > MAX_COMPONENT_BYTES {
        bail!("path component is too long");
    }
    if value.contains('/') || value.contains('\\') || value.chars().any(char::is_control) {
        bail!("path component contains a separator or control character");
    }
    Ok(())
}

pub fn validate_pass_path(path: &str) -> Result<String> {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        bail!("password-store path must be nonempty and relative");
    }
    if path.len() > MAX_PASS_PATH_BYTES {
        bail!("password-store path is too long");
    }
    let components: Vec<&str> = path.split('/').collect();
    for component in &components {
        validate_component(component)?;
    }
    Ok(components.join("/"))
}

pub fn field_path(prefix: &str, title: &str, section: &str, field: &str) -> Result<String> {
    validate_component(title).context("invalid item title")?;
    validate_component(section).context("invalid section name")?;
    validate_component(field).context("invalid field name")?;
    let suffix = format!("{title}/{section}/{field}");
    let path = if prefix.is_empty() {
        suffix
    } else {
        format!("{prefix}/{suffix}")
    };
    validate_pass_path(&path)
}

pub fn validate_path_graph<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut exact = HashSet::new();
    let mut folded = HashSet::new();
    for path in paths {
        let canonical = validate_pass_path(path)?;
        if !exact.insert(canonical.clone()) {
            bail!("duplicate password-store path in desired state");
        }
        let case_key: String = canonical.nfc().flat_map(char::to_lowercase).collect();
        if !folded.insert(case_key) {
            bail!("case-folding password-store path collision in desired state");
        }
    }
    Ok(())
}

pub fn ciphertext_path(store: &Path, pass_path: &str) -> Result<PathBuf> {
    let canonical = validate_pass_path(pass_path)?;
    let mut result = store.to_path_buf();
    for component in canonical.split('/') {
        result.push(component);
    }
    let mut filename = result
        .file_name()
        .context("password-store path has no filename")?
        .to_os_string();
    filename.push(".gpg");
    result.set_file_name(filename);
    if !result.starts_with(store) {
        bail!("password-store path escaped its root");
    }
    Ok(result)
}

pub fn ensure_no_symlinks(root: &Path, target: &Path) -> Result<()> {
    if !root.is_absolute() || !target.starts_with(root) {
        bail!("target is outside password-store root");
    }
    if let Ok(metadata) = fs::symlink_metadata(root) {
        if metadata.file_type().is_symlink() {
            bail!("password-store root must not be a symbolic link");
        }
    }

    let relative = target
        .strip_prefix(root)
        .context("target is outside password-store root")?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            bail!("target contains a non-normal component");
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("symbolic links are not allowed in managed paths");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error).context("cannot inspect managed path"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_natural_field_path() {
        assert_eq!(
            field_path("coding", "GitHub", "Tokens", "API").unwrap(),
            "coding/GitHub/Tokens/API"
        );
    }

    #[test]
    fn ciphertext_suffix_preserves_existing_extension() {
        assert_eq!(
            ciphertext_path(Path::new("/store"), "item/token.txt").unwrap(),
            PathBuf::from("/store/item/token.txt.gpg")
        );
    }

    #[test]
    fn rejects_traversal_and_separators() {
        for component in [
            "",
            ".",
            "..",
            ".git",
            ".proton-pass-sync-stage-fake",
            "a/b",
            "a\\b",
            "line\nbreak",
        ] {
            assert!(validate_component(component).is_err(), "{component:?}");
        }
    }

    #[test]
    fn rejects_case_and_unicode_normalization_collisions() {
        assert!(validate_path_graph(["Item/Field", "item/field"]).is_err());
        assert!(validate_path_graph(["caf\u{e9}/x", "cafe\u{301}/x"]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_ancestors() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("store");
        fs::create_dir(&root).unwrap();
        symlink(directory.path(), root.join("link")).unwrap();
        assert!(ensure_no_symlinks(&root, &root.join("link/file.gpg")).is_err());
    }
}
