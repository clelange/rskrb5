use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Empty,
    UnsupportedType { name_type: String },
}

pub(crate) fn file_path_from_name(name: &str, allowed_types: &[&str]) -> Result<PathBuf, Error> {
    if name.is_empty() {
        return Err(Error::Empty);
    }

    let Some((prefix, path)) = name.split_once(':') else {
        return Ok(PathBuf::from(name));
    };

    if is_windows_drive_path(prefix, path) {
        return Ok(PathBuf::from(name));
    }

    if allowed_types
        .iter()
        .any(|allowed| prefix.eq_ignore_ascii_case(allowed))
    {
        if path.is_empty() {
            return Err(Error::Empty);
        }
        Ok(PathBuf::from(path))
    } else {
        Err(Error::UnsupportedType {
            name_type: prefix.to_owned(),
        })
    }
}

fn is_windows_drive_path(prefix: &str, path: &str) -> bool {
    prefix.len() == 1
        && prefix.as_bytes()[0].is_ascii_alphabetic()
        && (path.starts_with('\\') || path.starts_with('/'))
}
