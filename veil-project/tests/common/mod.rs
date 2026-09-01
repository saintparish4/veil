//! Building throwaway projects on disk for the integration tests.
//!
//! Every test writes real files into a `TempDir` and loads them through the same
//! `Project::load` entry point the CLI uses. No in-memory shortcut: import
//! resolution is filesystem behaviour, and testing it against a fake filesystem
//! would test the fake.
//!
//! Each test binary compiles this module separately, so helpers used by only
//! some of them look dead to the others.

#![allow(dead_code)]

use std::path::Path;
use tempfile::TempDir;
use veil_project::Project;

/// Write `files` as `(relative path, contents)` into a fresh temp directory and
/// resolve the result.
pub fn project(files: &[(&str, &str)]) -> (TempDir, Project) {
    let dir = tempfile::tempdir().expect("temp dir");
    write_all(dir.path(), files);
    let project = Project::load(dir.path()).expect("load project");
    (dir, project)
}

pub fn write_all(root: &Path, files: &[(&str, &str)]) {
    for (rel, contents) in files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(&path, contents).expect("write fixture");
    }
}

/// A contract by name, panicking with a useful message when the fixture is wrong.
pub fn contract<'a>(project: &'a Project, name: &str) -> &'a veil_project::Contract {
    project
        .contracts
        .unique_by_name(name)
        .unwrap_or_else(|| panic!("no unique contract named `{name}` in fixture"))
}
