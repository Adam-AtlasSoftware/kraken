mod common;

use common::*;
use kraken_registry::{Registry, Session};
use serde_json::json;

#[tokio::test]
async fn firmware_identify_finds_the_gzip_and_the_elf_in_a_synthetic_image() {
    let env = Setup::new(tiny()).start().await;
    let fresh = Session::new(env.factory.clone());
    let r = Registry::standard();
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    let mut img = std::fs::read(corpus.join("raw/fw_cortexm.bin")).expect("firmware");
    let gzip_at = 8192usize;
    img.resize(gzip_at, 0xff);
    img.extend([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]);
    img.extend((0..6000u64).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8));
    img.resize(img.len().div_ceil(4096) * 4096, 0);
    let elf_at = img.len();
    img.extend(std::fs::read(corpus.join("bin/stripped_calc-O2-stripped")).expect("elf"));
    let path = env.tmp.path().join("synthetic.bin");
    std::fs::write(&path, &img).expect("write");

    let out = r
        .call_json(
            "firmware_identify",
            &fresh,
            &user(),
            json!({"path": path.to_str().unwrap()}),
        )
        .await
        .expect("identify");
    let sigs: Vec<(String, String)> = out["signatures"]
        .as_array()
        .expect("signatures")
        .iter()
        .map(|s| {
            (
                s["kind"].as_str().unwrap().to_string(),
                s["offset"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        sigs,
        [
            ("gzip".to_string(), format!("{gzip_at:#x}")),
            ("elf".to_string(), format!("{elf_at:#x}")),
        ],
        "{out}"
    );
    assert_eq!(out["size"], img.len());
    assert_eq!(out["entropy_block"], 4096);
    assert_eq!(
        out["entropy"].as_str().unwrap().len(),
        img.len().div_ceil(4096)
    );
    let kinds: Vec<_> = out["regions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"compressed_or_encrypted"), "{kinds:?}");

    if let Some(home) = kraken_registry::trust::home_dir() {
        let hidden = home.join(".ssh").join("id_ed25519");
        let e = r
            .call_json(
                "firmware_identify",
                &fresh,
                &agent("r1"),
                json!({"path": hidden.to_str().unwrap()}),
            )
            .await
            .expect_err("refused");
        assert!(e.message.contains("refused for agents"), "{}", e.message);
    }
}
