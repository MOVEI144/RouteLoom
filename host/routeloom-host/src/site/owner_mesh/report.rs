//! Run evidence (G6): with `ROUTELOOM_E2E_OUT` set, every world writes
//! `<out>/<tag>/run.json` (revision, topology, boot plan, seeds, clocks),
//! `metrics.json` (switch, noise and per-peer counters) and
//! `verdict.json` when it ends; a world that cannot start writes a
//! NOT_RUN verdict.

use super::*;
use routeloom_json::escape_string;

fn quoted(text: &str) -> String {
    format!("\"{}\"", escape_string(text))
}

fn out_dir(tag: &str) -> Option<std::path::PathBuf> {
    let dir = std::path::PathBuf::from(std::env::var_os("ROUTELOOM_E2E_OUT")?).join(tag);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn write(dir: &std::path::Path, name: &str, json: String) {
    std::fs::write(dir.join(name), json + "\n").expect("write E2E report");
}

fn list<T: std::fmt::Display>(items: impl IntoIterator<Item = T>) -> String {
    let items: Vec<String> = items.into_iter().map(|item| item.to_string()).collect();
    format!("[{}]", items.join(","))
}

fn matrix(rows: &[Vec<u64>]) -> String {
    list(rows.iter().map(list))
}

fn revision() -> String {
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        return sha;
    }
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn write_not_run(tag: &str) {
    if let Some(dir) = out_dir(tag) {
        write(
            &dir,
            "verdict.json",
            format!(
                "{{\"tag\":{},\"verdict\":\"NOT_RUN\",\"reason\":\"no C++ peers\"}}",
                quoted(tag)
            ),
        );
    }
}

pub(super) fn write_world(world: &MeshWorld, passed: bool) {
    let Some(dir) = out_dir(&world.tag) else {
        return;
    };
    let switch = &world.switch;
    let edges = (0..switch.nodes())
        .flat_map(|a| (a + 1..switch.nodes()).map(move |b| (a, b)))
        .filter(|&(a, b)| switch.base[a][b] || switch.base[b][a])
        .map(|(a, b)| format!("[{a},{b}]"));
    write(
        &dir,
        "run.json",
        format!(
            "{{\"tag\":{},\"revision\":{},\"nodes\":{},\"edges\":{},\"boot_ms\":{},\
             \"peer_seeds\":{},\"noise_seed\":{},\"vt_ms\":{},\"wall_ms\":{},\
             \"phase0_wall_ms\":{}}}",
            quoted(&world.tag),
            quoted(&revision()),
            switch.nodes(),
            list(edges),
            list(&world.boot_ms),
            list(world.peers.iter().map(|peer| peer.seed)),
            switch.noise_seed,
            world.now - world.started_vt,
            world.started.elapsed().as_millis(),
            world.phase0_wall_ms,
        ),
    );
    let noise = switch.noise_hits;
    let peers = world.peers.iter().zip(&world.snaps).map(|(peer, snap)| {
        let delivered = snap
            .app_tx
            .iter()
            .filter(|tx| tx.state == DELIVERY_DELIVERED)
            .count();
        format!(
            "{{\"node\":\"{:#x}\",\"reboots\":{},\"sends\":{},\"send_failures\":{},\
             \"app_tx\":{},\"app_tx_delivered\":{},\"rx_count\":{},\"no_route\":{},\
             \"queued\":{},\"rx_queue_max\":{},\"owner_polls\":{},\"hop_accept_expired\":{}}}",
            peer.node,
            peer.reboots,
            snap.sends,
            snap.send_failures,
            snap.app_tx.len(),
            delivered,
            snap.rx_count,
            snap.no_route,
            snap.queued,
            snap.rx_queue_max,
            snap.owner_polls,
            snap.hop_accept_expired,
        )
    });
    write(
        &dir,
        "metrics.json",
        format!(
            "{{\"switch\":{{\"delivered\":{},\"dropped\":{},\"wire_dropped\":{},\
             \"noise\":{{\"lost\":{},\"duplicated\":{},\"reordered\":{},\"jittered\":{}}},\
             \"leg_delivered\":{},\"leg_dropped\":{}}},\"usb_auth_sessions\":{},\"peers\":{}}}",
            switch.delivered,
            switch.dropped,
            switch.wire_dropped,
            noise.lost,
            noise.duplicated,
            noise.reordered,
            noise.jittered,
            matrix(&switch.leg_delivered),
            matrix(&switch.leg_dropped),
            world.usb_auth_total(),
            list(peers),
        ),
    );
    write(
        &dir,
        "verdict.json",
        format!(
            "{{\"tag\":{},\"verdict\":\"{}\",\"noise_hits\":{},\"rule_hits\":{}}}",
            quoted(&world.tag),
            if passed { "PASS" } else { "FAIL" },
            noise.total(),
            u64::from(switch.wire_dropped) + u64::from(switch.notice_chunks_dropped),
        ),
    );
}
