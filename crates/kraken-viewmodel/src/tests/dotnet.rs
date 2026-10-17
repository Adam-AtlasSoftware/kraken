//! A .NET project through a scripted backend: C# decompilation and navigation by managed
//! locator (the registry gives a method's metadata token as `address` and the assembly's MVID as
//! `module`).

use super::*;

const MVID: &str = "61a35c05-1940-4673-81a7-f2157a66b75c";

fn managed_fn(token: u64, name: &str) -> Value {
    let mut v = fn_view(token, name);
    v["module"] = json!(MVID);
    v["signature"] = u(&format!("void {name}()"));
    v
}

fn token_of(a: &Value) -> u64 {
    let hex = a["address"].as_str().expect("an address");
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("a hex address")
}

/// The replies of a .NET project as the registry gives them.
fn dotnet_backend() -> FakeBackend {
    let mut project = project_json("not_started");
    project["program"] = json!({
        "arch": "cil", "format": "dotnet", "base": "0x400000", "sha256": "00", "size": 5632,
    });
    FakeBackend::new()
        .reply("project_open", project.clone())
        .reply("project_info", project)
        .reply(
            "list_functions",
            page(
                vec![
                    managed_fn(0x0600_0001, "Main"),
                    managed_fn(0x0600_0002, "Greet"),
                ],
                None,
            ),
        )
        .reply("history", page(vec![], None))
        .reply("proposals_list", page(vec![], None))
        .on("get_function", |a| {
            assert_eq!(a["module"], MVID, "get_function names the module: {a}");
            let token = token_of(a);
            let name = if token == 0x0600_0001 {
                "Main"
            } else {
                "Greet"
            };
            let mut d = managed_fn(token, name);
            d["comments"] = json!([]);
            d["versions"] = json!({});
            Ok(d)
        })
        .on("decompile", |a| {
            assert_eq!(a["module"], MVID, "decompile names the module: {a}");
            let (text, tokens) = match token_of(a) {
                0x0600_0001 => (
                    "static void Main()\n{\n    Greet();\n}\n",
                    // `Main` is at 12..16 and the call to `Greet` at 24..29.
                    json!([
                        {"start": 0, "end": 6, "kind": "keyword"},
                        {"start": 7, "end": 11, "kind": "keyword"},
                        {"start": 12, "end": 16, "kind": "function"},
                        {"start": 24, "end": 29, "kind": "function",
                         "target": "0x6000002", "target_module": MVID},
                    ]),
                ),
                _ => (
                    "static void Greet()\n{\n}\n",
                    json!([{"start": 12, "end": 17, "kind": "function"}]),
                ),
            };
            Ok(json!({
                "address": a["address"],
                "module": MVID,
                "language": "csharp",
                "text": u(text),
                "truncated": false,
                "tokens": tokens,
                "references": [{"name": u("Greet"), "address": "0x6000002", "module": MVID}],
                "warnings": [],
                "completeness": {"kind": "complete"},
            }))
        })
}

#[test]
fn a_dotnet_project_shows_csharp_and_follows_managed_locators() {
    let mut r = opened(dotnet_backend());
    assert_eq!(r.vm.project.as_ref().unwrap().format, "dotnet");
    assert_eq!(r.vm.module.as_deref(), Some(MVID), "learned from the list");
    let addrs: Vec<u64> = r.vm.functions.items.iter().map(|f| f.address).collect();
    assert_eq!(addrs, vec![0x0600_0001, 0x0600_0002]);

    r.vm.select_function(0x0600_0001);
    assert!(r.vm.block_until_idle(WAIT));
    let cur = r.vm.current.as_ref().unwrap();
    assert_eq!(cur.name, "Main");
    let d = cur.decompiled.ready().expect("decompiled").clone();
    assert_eq!(d.result.language, "csharp");
    assert!(d.result.text.contains("Greet();"));
    assert_eq!(
        d.result.function,
        kraken_proto::Locator::managed(MVID, 0x0600_0001)
    );
    d.result.validate_tokens().expect("valid tokens");

    // The call to Greet carries a managed locator; following it opens that method.
    let call = d
        .result
        .tokens
        .iter()
        .find(|t| t.target.is_some())
        .expect("a followable token");
    assert_eq!(call.kind, TokenKind::Function);
    let target = call.target.clone().expect("a target");
    assert_eq!(target, kraken_proto::Locator::managed(MVID, 0x0600_0002));
    let kraken_proto::Locator::Managed { token, .. } = target else {
        panic!("not a managed locator");
    };
    r.vm.navigate_to(u64::from(token));
    assert!(r.vm.block_until_idle(WAIT));
    let cur = r.vm.current.as_ref().unwrap();
    assert_eq!(cur.name, "Greet");
    let text = &cur.decompiled.ready().expect("decompiled").result.text;
    assert!(text.contains("static void Greet()"), "{text}");

    // Back goes to Main again; every request named the module.
    r.vm.go_back();
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.current.as_ref().unwrap().name, "Main");
    let asked: Vec<String> = r
        .backend
        .calls_to("decompile")
        .iter()
        .map(|a| {
            format!(
                "{}/{}",
                a["address"].as_str().unwrap_or(""),
                a["module"].as_str().unwrap_or("")
            )
        })
        .collect();
    assert_eq!(
        asked,
        vec![
            format!("0x6000001/{MVID}"),
            format!("0x6000002/{MVID}"),
            format!("0x6000001/{MVID}"),
        ]
    );
}

#[test]
fn native_projects_never_send_a_module() {
    let mut r = opened(base_backend());
    assert_eq!(r.vm.module, None);
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    for a in r.backend.calls_to("decompile") {
        assert!(a.get("module").is_none(), "{a}");
    }
}
