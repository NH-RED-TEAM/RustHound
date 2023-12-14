use std::process::Command;

/// Function to run commands
pub fn run(input: &str) -> String
{
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
                .args(["/k",input])
                .output()
                .expect("failed")
    } else {
        Command::new("sh")
                .arg("-c")
                .arg(input)
                .output()
                .expect("failed")
    };
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        format!("{}", stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        format!("[FAILED] Command error:\n{}", stderr)
    }
}