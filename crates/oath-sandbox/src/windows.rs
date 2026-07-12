use crate::{BackendCapabilities, SandboxPlan};
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, process::ExitStatus};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FreeSid, HANDLE, LocalFree, PSID},
    Security::{
        Authorization::ConvertSidToStringSidW,
        CreateRestrictedToken, DISABLE_MAX_PRIVILEGE,
        Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile},
        OpenProcessToken, SECURITY_CAPABILITIES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
        TOKEN_QUERY,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
        Threading::{
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
            GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
            STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

pub fn capabilities() -> BackendCapabilities {
    BackendCapabilities {
        backend: "windows-appcontainer-job-v2".into(),
        available: true,
        filesystem_isolation: true,
        network_isolation: true,
        process_isolation: true,
        resource_limits: true,
        degraded_reason: None,
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn remove_acl_grant(sid_text: &str, path: &std::path::Path) {
    let _ = std::process::Command::new("icacls.exe")
        .arg(path)
        .arg("/remove")
        .arg(format!("*{sid_text}"))
        .arg("/T")
        .arg("/Q")
        .status();
}

unsafe fn grant_workdir(sid: PSID, paths: &[std::path::PathBuf]) -> anyhow::Result<String> {
    let mut string_sid: *mut u16 = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { ConvertSidToStringSidW(sid, &mut string_sid) } != 0,
        "ConvertSidToStringSidW failed"
    );
    let mut length = 0;
    while unsafe { *string_sid.add(length) } != 0 {
        length += 1;
    }
    let sid_text = String::from_utf16(unsafe { std::slice::from_raw_parts(string_sid, length) })?;
    let _ = unsafe { LocalFree(string_sid.cast()) };
    for (index, path) in paths.iter().enumerate() {
        let status = std::process::Command::new("icacls.exe")
            .arg(path)
            .arg("/grant")
            .arg(format!("*{sid_text}:(OI)(CI)M"))
            .arg("/T")
            .arg("/Q")
            .status()?;
        if !status.success() {
            for granted in &paths[..=index] {
                remove_acl_grant(&sid_text, granted);
            }
            anyhow::bail!("failed to grant AppContainer access to {}", path.display());
        }
    }
    Ok(sid_text)
}

struct AppContainerProfileGuard {
    moniker: Vec<u16>,
    sid_text: String,
    paths: Vec<std::path::PathBuf>,
}

impl Drop for AppContainerProfileGuard {
    fn drop(&mut self) {
        for path in &self.paths {
            remove_acl_grant(&self.sid_text, path);
        }
        // SAFETY: moniker is a live, NUL-terminated UTF-16 profile name created
        // by this launch and is not used after the guard is dropped.
        unsafe {
            let _ = DeleteAppContainerProfile(self.moniker.as_ptr());
        }
    }
}

pub fn run(
    plan: &SandboxPlan,
    program: &std::path::Path,
    args: &[String],
) -> anyhow::Result<ExitStatus> {
    anyhow::ensure!(
        plan.network == crate::NetworkMode::Deny,
        "Windows AppContainer outbound network grants are not implemented; refusing degraded execution"
    );
    // SAFETY: every pointer below refers to an owned buffer kept alive through process creation;
    // every successfully created Windows handle/SID/attribute list is released exactly once.
    unsafe {
        let mut source: HANDLE = std::ptr::null_mut();
        anyhow::ensure!(
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                &mut source
            ) != 0,
            "OpenProcessToken failed: {}",
            std::io::Error::last_os_error()
        );
        let mut restricted: HANDLE = std::ptr::null_mut();
        if CreateRestrictedToken(
            source,
            DISABLE_MAX_PRIVILEGE,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut restricted,
        ) == 0
        {
            CloseHandle(source);
            anyhow::bail!(
                "CreateRestrictedToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        CloseHandle(source);

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let moniker_text = format!("Oath.PackageSandbox.{}.{}", std::process::id(), nonce);
        let moniker = wide(OsStr::new(&moniker_text));
        let display = wide(OsStr::new("Oath package sandbox"));
        let description = wide(OsStr::new("Restricted Oath package execution"));
        let mut sid: PSID = std::ptr::null_mut();
        let result = CreateAppContainerProfile(
            moniker.as_ptr(),
            display.as_ptr(),
            description.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        );
        if result < 0 {
            CloseHandle(restricted);
            anyhow::bail!("AppContainer profile unavailable: HRESULT {result:#x}");
        }
        let sid_text = match grant_workdir(sid, &plan.writable_paths) {
            Ok(sid_text) => sid_text,
            Err(error) => {
                FreeSid(sid);
                CloseHandle(restricted);
                let _ = DeleteAppContainerProfile(moniker.as_ptr());
                return Err(error);
            }
        };
        let _profile = AppContainerProfileGuard {
            moniker,
            sid_text,
            paths: plan.writable_paths.clone(),
        };

        let mut attribute_size = 0usize;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attribute_size);
        let mut attribute_storage = vec![0u8; attribute_size];
        let attributes = attribute_storage.as_mut_ptr().cast();
        if InitializeProcThreadAttributeList(attributes, 1, 0, &mut attribute_size) == 0 {
            FreeSid(sid);
            CloseHandle(restricted);
            anyhow::bail!("InitializeProcThreadAttributeList failed");
        }
        let mut security = SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        if UpdateProcThreadAttribute(
            attributes,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &mut security as *mut _ as *mut _,
            std::mem::size_of_val(&security),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            DeleteProcThreadAttributeList(attributes);
            FreeSid(sid);
            CloseHandle(restricted);
            anyhow::bail!("AppContainer security attribute failed");
        }

        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            DeleteProcThreadAttributeList(attributes);
            FreeSid(sid);
            CloseHandle(restricted);
            anyhow::bail!("CreateJobObjectW failed");
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.BasicLimitInformation.ActiveProcessLimit = if plan.allow_subprocesses {
            plan.limits.max_processes.try_into().unwrap_or(u32::MAX)
        } else {
            1
        };
        limits.JobMemoryLimit = plan
            .limits
            .max_memory_bytes
            .try_into()
            .unwrap_or(usize::MAX);
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            std::mem::size_of_val(&limits) as u32,
        ) == 0
        {
            CloseHandle(job);
            DeleteProcThreadAttributeList(attributes);
            FreeSid(sid);
            CloseHandle(restricted);
            anyhow::bail!("SetInformationJobObject failed");
        }

        let mut command = quote(&program.display().to_string());
        for arg in args {
            command.push(' ');
            command.push_str(&quote(arg));
        }
        let mut command = wide(OsStr::new(&command));
        let application = wide(program.as_os_str());
        let cwd = wide(plan.workdir.as_os_str());
        let mut environment = Vec::new();
        for name in &plan.environment_allowlist {
            if let Ok(value) = std::env::var(name) {
                environment.extend(wide(OsStr::new(&format!("{name}={value}"))));
            }
        }
        environment.push(0);
        let mut startup: STARTUPINFOEXW = std::mem::zeroed();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes;
        let mut process: PROCESS_INFORMATION = std::mem::zeroed();
        let created = CreateProcessAsUserW(
            restricted,
            application.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut process,
        );
        DeleteProcThreadAttributeList(attributes);
        FreeSid(sid);
        CloseHandle(restricted);
        if created == 0 {
            CloseHandle(job);
            anyhow::bail!(
                "CreateProcessAsUserW AppContainer launch failed: {}",
                std::io::Error::last_os_error()
            );
        }
        if AssignProcessToJobObject(job, process.hProcess) == 0 {
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            CloseHandle(job);
            anyhow::bail!("AssignProcessToJobObject failed");
        }
        if ResumeThread(process.hThread) == u32::MAX {
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            CloseHandle(job);
            anyhow::bail!("ResumeThread failed");
        }
        WaitForSingleObject(process.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(process.hProcess, &mut code);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(job);
        use std::os::windows::process::ExitStatusExt;
        Ok(ExitStatus::from_raw(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restricted_appcontainer_job_launches_and_exits() {
        let root =
            std::env::temp_dir().join(format!("oath-windows-sandbox-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let plan = SandboxPlan::strict("windows-smoke", root);
        let status = run(
            &plan,
            std::path::Path::new("C:\\Windows\\System32\\cmd.exe"),
            &["/C".into(), "exit 0".into()],
        )
        .unwrap();
        assert!(status.success());
    }

    #[test]
    fn appcontainer_strips_unapproved_environment() {
        let root = std::env::temp_dir().join(format!("oath-windows-env-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        // SAFETY: this target-specific test controls the variable for one child launch.
        unsafe { std::env::set_var("OATH_WINDOWS_TEST_SECRET", "must-not-leak") };
        let plan = SandboxPlan::strict("windows-env", root);
        let status = run(
            &plan,
            std::path::Path::new("C:\\Windows\\System32\\cmd.exe"),
            &[
                "/C".into(),
                "if defined OATH_WINDOWS_TEST_SECRET (exit /b 1) else (exit /b 0)".into(),
            ],
        )
        .unwrap();
        unsafe { std::env::remove_var("OATH_WINDOWS_TEST_SECRET") };
        assert!(status.success(), "restricted child inherited a secret");
    }

    #[test]
    fn appcontainer_denies_writes_outside_scoped_root() {
        let root = std::env::temp_dir().join(format!("oath-windows-root-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let plan = SandboxPlan::strict("windows-filesystem", root);
        let escape = format!("C:\\oath-appcontainer-escape-{}.txt", std::process::id());
        let status = run(
            &plan,
            std::path::Path::new("C:\\Windows\\System32\\cmd.exe"),
            &["/C".into(), format!("(echo escape) > {escape}")],
        )
        .unwrap();
        assert!(!status.success(), "AppContainer wrote outside its ACL root");
        assert!(!std::path::Path::new(&escape).exists());
    }

    #[test]
    fn appcontainer_denies_network_without_capability() {
        let root =
            std::env::temp_dir().join(format!("oath-windows-network-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let plan = SandboxPlan::strict("windows-network", root);
        let status = run(
            &plan,
            std::path::Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            &[
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                "$ErrorActionPreference='Stop'; Invoke-WebRequest -TimeoutSec 2 http://1.1.1.1; exit 0".into(),
            ],
        )
        .unwrap();
        assert!(
            !status.success(),
            "AppContainer unexpectedly reached the network"
        );
    }
}
