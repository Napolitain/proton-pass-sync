use anyhow::{bail, Context, Result};
use rlimit::Resource;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use wait_timeout::ChildExt;
use zeroize::Zeroize;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const OUTPUT_LIMIT: usize = 64 * 1024 * 1024;

pub fn disable_core_dumps() -> Result<()> {
    Resource::CORE
        .set(0, 0)
        .context("cannot disable process core dumps")
}

pub fn run_checked(
    program: &Path,
    args: &[OsString],
    stdin: Option<&[u8]>,
    environment: &[(OsString, OsString)],
    remove_environment: &[&str],
    failure_label: &'static str,
) -> Result<Vec<u8>> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in environment {
        command.env(key, value);
    }
    for key in remove_environment {
        command.env_remove(key);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("{failure_label}: executable could not be started"))?;
    let stdout = child.stdout.take().context("cannot capture child output")?;
    let stderr = child
        .stderr
        .take()
        .context("cannot capture child diagnostics")?;
    let stdout_reader = thread::spawn(move || read_limited(stdout));
    let stderr_reader = thread::spawn(move || read_limited(stderr));

    if let Some(input) = stdin {
        let mut child_stdin = child.stdin.take().context("cannot open child input")?;
        if child_stdin.write_all(input).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            bail!("{failure_label}: input was rejected");
        }
    }

    let Some(status) = child
        .wait_timeout(COMMAND_TIMEOUT)
        .context("cannot wait for child process")?
    else {
        let _ = child.kill();
        let _ = child.wait();
        let mut stdout = join_reader(stdout_reader)?;
        let mut stderr = join_reader(stderr_reader)?;
        stdout.zeroize();
        stderr.zeroize();
        bail!("{failure_label}: command timed out");
    };

    let mut stdout = join_reader(stdout_reader)?;
    let mut stderr = join_reader(stderr_reader)?;
    let oversized = stdout.len() > OUTPUT_LIMIT || stderr.len() > OUTPUT_LIMIT;
    if !status.success() || oversized {
        stdout.zeroize();
        stderr.zeroize();
        if oversized {
            bail!("{failure_label}: command output exceeded the safety limit");
        }
        bail!("{failure_label}: command failed");
    }
    stderr.zeroize();
    Ok(stdout)
}

fn read_limited(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if output.len() <= OUTPUT_LIMIT {
            let remaining = OUTPUT_LIMIT.saturating_add(1).saturating_sub(output.len());
            output.extend_from_slice(&buffer[..count.min(remaining)]);
        }
    }
    buffer.zeroize();
    Ok(output)
}

fn join_reader(handle: thread::JoinHandle<std::io::Result<Vec<u8>>>) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("child output reader failed"))?
        .context("cannot read child output")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_successful_output() {
        let output = run_checked(
            Path::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from("printf ok")],
            None,
            &[],
            &[],
            "test command",
        )
        .unwrap();
        assert_eq!(output, b"ok");
    }

    #[test]
    fn does_not_surface_child_diagnostics() {
        let error = run_checked(
            Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from("printf supersecret >&2; exit 1"),
            ],
            None,
            &[],
            &[],
            "test command",
        )
        .unwrap_err();
        assert!(!error.to_string().contains("supersecret"));
    }
}
