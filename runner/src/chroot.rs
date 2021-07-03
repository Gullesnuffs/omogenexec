use libc_bindings::{chdir, chroot, mount, mount_proc, MountOption};
use std::{
    path::{Path, PathBuf},
    result::Result,
};

pub struct Mount {
    inside: PathBuf,
    outside: Option<PathBuf>,
    writable: bool,
}

pub fn read_only_copy_mount(path: PathBuf) -> Mount {
    Mount {
        inside: path,
        outside: None,
        writable: false,
    }
}

pub fn writable_mount(path: PathBuf) -> Mount {
    Mount {
        inside: path,
        outside: None,
        writable: true,
    }
}

pub fn mount_procfs(root: &Path) {
    let proc_path = root.join("proc");
    std::fs::create_dir_all(proc_path.as_path()).unwrap();
    mount_proc(
        Path::new("/proc"),
        proc_path.as_path(),
        MountOption::NoDev | MountOption::NoExec | MountOption::NoSuid,
    )
    .unwrap();
}

pub fn make_mount(root: &Path, mount_opts: &Mount) -> Result<(), String> {
    if !mount_opts.inside.is_absolute() {
        return Err(format!(
            "Mount path {:?} is not absolute",
            mount_opts.inside
        ));
    }
    let target = root.join(mount_opts.inside.as_path().strip_prefix("/").unwrap());
    let target_path = target.as_path();
    let outside = match &mount_opts.outside {
        None => mount_opts.inside.as_path(),
        Some(path) => path.as_path(),
    };
    std::fs::create_dir_all(&target).unwrap();

    // NoDev: ensure we can't access special devices somehow in our sandbox.
    // NoSuid: don't allow the sandboxed program to do anything as root by calling some setuid
    // programs.
    let mut base_opts =
        MountOption::Bind | MountOption::NoSuid | MountOption::NoDev | MountOption::Private;
    if !mount_opts.writable {
        base_opts |= MountOption::ReadOnly;
    }
    match mount(outside, target_path, base_opts) {
        Err(e) => return Err(e),
        Ok(()) => {}
    };
    // When BIND:ing using mount, read-only (and possible other flags) may
    // require a remount to take effect (see e.g.
    // https://lwn.net/Articles/281157/).
    base_opts |= MountOption::Remount;
    mount(outside, target_path, base_opts)
}

pub fn apply_chroot(container_path: &Path) {
    chroot(&container_path).unwrap();
    chdir(&PathBuf::from("/")).unwrap();
}