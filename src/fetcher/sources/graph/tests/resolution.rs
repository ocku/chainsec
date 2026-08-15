use super::*;

#[test]
fn graph_module_extensions_preserve_jsx_and_tsx() {
    for (url, expected) in [
        ("https://example.test/component.jsx", "jsx"),
        ("https://example.test/component.tsx", "tsx"),
    ] {
        assert_eq!(module_extension(&Url::parse(url).unwrap()), expected);
    }
}

#[test]
fn graph_resolution_collects_imports_from_jsx_and_tsx_modules() {
    let cases = [
        (
            "jsx",
            b"const view = <Component />; import './jsx-child.js';".as_slice(),
            "https://example.test/jsx-child.js",
        ),
        (
            "tsx",
            b"const view: JSX.Element = <Component />; import './tsx-child.ts';".as_slice(),
            "https://example.test/tsx-child.ts",
        ),
    ];

    for (extension, source, expected) in cases {
        let base = Url::parse(&format!("https://example.test/component.{extension}")).unwrap();
        assert_eq!(
            resolve_graph_modules(&base, source, extension).unwrap(),
            [Url::parse(expected).unwrap()]
        );
    }
}

#[test]
fn graph_resolution_rejects_unmaterialized_registry_specifiers() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    for specifier in ["npm:package@1.0.0", "jsr:@scope/package@1.0.0"] {
        let error = resolve_graph_modules(&base, format!("import {specifier:?};").as_bytes(), "ts")
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("Deno graph resolution"));
        assert!(message.contains(specifier));
        assert!(message.contains("https://example.test/root.ts"));
        assert!(message.contains("incomplete"));
    }
}

#[test]
fn graph_resolution_rejects_unsupported_dynamic_imports() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    let error =
        resolve_graph_modules(&base, b"await import(\"npm:package@1.0.0\");", "ts").unwrap_err();

    assert!(error.to_string().contains("npm:package@1.0.0"));
    assert!(error.to_string().contains("incomplete"));
}

#[test]
fn graph_resolution_rejects_other_unsupported_static_literals() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    for specifier in [
        "node:fs",
        "data:text/javascript,export{}",
        "package",
        "loader:package",
    ] {
        let error = resolve_graph_modules(&base, format!("import {specifier:?};").as_bytes(), "ts")
            .unwrap_err();
        assert!(error.to_string().contains(specifier));
        assert!(error.to_string().contains("incomplete"));
    }

    let error = resolve_graph_modules(&base, b"import \"./%\";", "ts").unwrap_err();
    assert!(error.to_string().contains("invalid"));
    assert!(error.to_string().contains("incomplete"));
}

#[test]
fn graph_resolution_retains_http_and_url_relative_modules() {
    let base = Url::parse("https://example.test/path/root.ts").unwrap();

    let modules = resolve_graph_modules(
        &base,
        b"import \"https://cdn.example.test/module.ts\"; import \"./child.ts\";",
        "ts",
    )
    .unwrap();

    assert_eq!(
        modules,
        [
            Url::parse("https://cdn.example.test/module.ts").unwrap(),
            Url::parse("https://example.test/path/child.ts").unwrap(),
        ]
    );
}

#[test]
fn graph_resolution_decodes_escaped_static_specifiers() {
    let base = Url::parse("https://example.test/path/root.ts").unwrap();

    let modules = resolve_graph_modules(
            &base,
            br#"import "./\x65vil.ts"; export { value } from "./\u0065xport.ts"; await import("./d\u{79}namic.ts");"#,
            "ts",
        )
        .unwrap();

    assert_eq!(
        modules,
        [
            Url::parse("https://example.test/path/evil.ts").unwrap(),
            Url::parse("https://example.test/path/export.ts").unwrap(),
            Url::parse("https://example.test/path/dynamic.ts").unwrap(),
        ]
    );
}

#[test]
fn graph_resolution_decodes_escaped_url_characters() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    let modules = resolve_graph_modules(
        &base,
        br#"import "https:\u002f\u002fcdn.example.test\u002fmodule.ts";"#,
        "ts",
    )
    .unwrap();

    assert_eq!(
        modules,
        [Url::parse("https://cdn.example.test/module.ts").unwrap()]
    );
}

#[test]
fn graph_resolution_rejects_malformed_escaped_specifiers() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    for source in [
        br#"import "./\x6";"#.as_slice(),
        br#"import "./\u{110000}.ts";"#.as_slice(),
    ] {
        let error = resolve_graph_modules(&base, source, "ts").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("https://example.test/root.ts"));
        assert!(message.contains("decode"));
        assert!(message.contains("incomplete"));
    }
}

#[test]
fn nonliteral_dynamic_import_is_not_collected() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    assert!(
        resolve_graph_modules(&base, b"await import(module_name);", "ts")
            .unwrap()
            .is_empty()
    );
}
