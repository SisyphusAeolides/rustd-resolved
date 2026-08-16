#![allow(warnings)]
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn command(program: &OsString, args: &[OsString]) -> ExitStatus {
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("failed to execute {program:?}: {error}"));
    assert!(status.success(), "command {program:?} failed with {status}");
    status
}

fn object(out_dir: &Path, name: &str) -> PathBuf {
    out_dir.join(format!("{name}.o"))
}

fn compile_c(cc: &OsString, source: &str, output: &Path) {
    command(
        cc,
        &[
            OsString::from("-c"),
            OsString::from("-std=c17"),
            OsString::from("-O2"),
            OsString::from("-fPIC"),
            OsString::from("-fstack-protector-strong"),
            OsString::from("-U_FORTIFY_SOURCE"),
            OsString::from("-D_FORTIFY_SOURCE=3"),
            OsString::from("-Wall"),
            OsString::from("-Wextra"),
            OsString::from("-Werror"),
            OsString::from("-Iffi"),
            OsString::from(source),
            OsString::from("-o"),
            output.as_os_str().to_owned(),
        ],
    );
}

fn main() {
    println!("cargo:rerun-if-changed=ffi/native.c");
    println!("cargo:rerun-if-changed=ffi/interface.c");
    println!("cargo:rerun-if-changed=ffi/tls.c");
    println!("cargo:rerun-if-changed=ffi/dnssec.c");
    println!("cargo:rerun-if-changed=ffi/netlink.c");
    println!("cargo:rerun-if-changed=ffi/networkd.c");
    println!("cargo:rerun-if-changed=ffi/mdns.c");
    println!("cargo:rerun-if-changed=ffi/llmnr_mcast.c");
    println!("cargo:rerun-if-changed=ffi/native.h");
    println!("cargo:rerun-if-changed=ffi/routing.f90");
    println!("cargo:rerun-if-changed=ffi/iouring_dns.c");
    println!("cargo:rerun-if-changed=ffi/routing_score.f90");

    let target = env::var("CARGO_CFG_TARGET_OS").expect("target OS is set by cargo");
    assert!(
        target == "linux",
        "rustd-resolved currently supports Linux only"
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::create_dir_all(&out_dir).expect("create build output directory");

    let cc = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let ar = env::var_os("AR").unwrap_or_else(|| OsString::from("ar"));
    let native_obj = object(&out_dir, "resolved_native");
    let interface_obj = object(&out_dir, "resolved_interface");
    let tls_obj = object(&out_dir, "resolved_tls");
    let dnssec_obj = object(&out_dir, "resolved_dnssec");
    let netlink_obj = object(&out_dir, "resolved_netlink");
    let networkd_obj = object(&out_dir, "resolved_networkd");
    let mdns_obj = object(&out_dir, "resolved_mdns");
    let iouring_dns_obj = object(&out_dir, "resolved_iouring_dns");
    let llmnr_mcast_obj = object(&out_dir, "resolved_llmnr_mcast");
    let nss_resolve_shm_obj = object(&out_dir, "resolved_nss_resolve_shm");
    compile_c(&cc, "ffi/native.c", &native_obj);
    compile_c(&cc, "ffi/interface.c", &interface_obj);
    compile_c(&cc, "ffi/tls.c", &tls_obj);
    compile_c(&cc, "ffi/dnssec.c", &dnssec_obj);
    compile_c(&cc, "ffi/netlink.c", &netlink_obj);
    compile_c(&cc, "ffi/networkd.c", &networkd_obj);
    compile_c(&cc, "ffi/mdns.c", &mdns_obj);
    compile_c(&cc, "ffi/iouring_dns.c", &iouring_dns_obj);
    compile_c(&cc, "ffi/llmnr_mcast.c", &llmnr_mcast_obj);
    compile_c(&cc, "nss/nss_resolve_shm.c", &nss_resolve_shm_obj);

    let mut objects = vec![
        native_obj,
        interface_obj,
        tls_obj,
        dnssec_obj,
        netlink_obj,
        networkd_obj,
        mdns_obj,
        iouring_dns_obj,
        llmnr_mcast_obj,
        nss_resolve_shm_obj,
    ];

    println!("cargo:rerun-if-changed=nss/nss_resolve_shm.c");
    println!("cargo:rerun-if-changed=src/supremacy/");

    if env::var_os("CARGO_FEATURE_BEAST_WIRE").is_some() {
        let beast_wire_obj = object(&out_dir, "resolved_beast_wire");
        command(
            &cc,
            &[
                OsString::from("-c"),
                OsString::from("-std=c17"),
                OsString::from("-O3"),
                OsString::from("-fPIC"),
                OsString::from("-fstack-protector-strong"),
                OsString::from("-U_FORTIFY_SOURCE"),
                OsString::from("-D_FORTIFY_SOURCE=3"),
                OsString::from("-Wall"),
                OsString::from("-Wextra"),
                OsString::from("-Werror"),
                OsString::from("-Iffi"),
                OsString::from("ffi/beast_wire.c"),
                OsString::from("-o"),
                beast_wire_obj.clone().into_os_string(),
            ],
        );
        objects.push(beast_wire_obj);
        println!("cargo:rerun-if-changed=ffi/beast_wire.c");
    }

    let fortran_enabled = env::var_os("CARGO_FEATURE_FORTRAN_ROUTING").is_some();
    if fortran_enabled {
        let fc = env::var_os("FC").unwrap_or_else(|| OsString::from("gfortran"));
        let fortran_obj = object(&out_dir, "resolved_routing");
        let fortran_score_obj = object(&out_dir, "resolved_routing_score");
        command(
            &fc,
            &[
                OsString::from("-c"),
                OsString::from("-std=f2018"),
                OsString::from("-O2"),
                OsString::from("-fPIC"),
                OsString::from("-fimplicit-none"),
                OsString::from("-Wall"),
                OsString::from("-Wextra"),
                OsString::from("-Werror"),
                OsString::from(format!("-J{}", out_dir.display())),
                OsString::from("ffi/routing.f90"),
                OsString::from("-o"),
                fortran_obj.clone().into_os_string(),
            ],
        );
        command(
            &fc,
            &[
                OsString::from("-c"),
                OsString::from("-O3"),
                OsString::from("-fPIC"),
                OsString::from("-J"),
                OsString::from(out_dir.display().to_string()),
                OsString::from("ffi/routing_score.f90"),
                OsString::from("-o"),
                fortran_score_obj.clone().into_os_string(),
            ],
        );
        objects.push(fortran_obj);
        objects.push(fortran_score_obj);
    }

    if env::var_os("CARGO_FEATURE_KALMAN").is_some() {
        let fc = env::var_os("FC").unwrap_or_else(|| OsString::from("gfortran"));
        let kalman_obj = object(&out_dir, "resolved_kalman_upstream");
        command(
            &fc,
            &[
                OsString::from("-c"),
                OsString::from("-O3"),
                OsString::from("-fPIC"),
                OsString::from("-J"),
                OsString::from(out_dir.display().to_string()),
                OsString::from("ffi/kalman_upstream.f90"),
                OsString::from("-o"),
                kalman_obj.clone().into_os_string(),
            ],
        );
        objects.push(kalman_obj);
        println!("cargo:rerun-if-changed=ffi/kalman_upstream.f90");
    }

    let archive = out_dir.join("libresolved_native.a");
    let mut args = vec![OsString::from("crs"), archive.clone().into_os_string()];
    args.extend(objects.into_iter().map(PathBuf::into_os_string));
    command(&ar, &args);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=resolved_native");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=uring");
    if fortran_enabled || env::var_os("CARGO_FEATURE_KALMAN").is_some() {
        println!("cargo:rustc-link-lib=gfortran");
    }
}
