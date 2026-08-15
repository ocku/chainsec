use super::{
    DEFAULT_MAX_ACQUISITION_SECONDS, DEFAULT_MAX_NETWORK_REQUESTS, DEFAULT_MAX_PACKAGES,
    DEFAULT_MAX_REDIRECT_HOPS, DEFAULT_MAX_SOURCE_FILE_SIZE, EngineLimits, SerializableLimits,
};

#[test]
fn serializable_limits_include_network_acquisition_bounds() {
    let limits = EngineLimits::default();
    let serialized = SerializableLimits::from(&limits);

    assert_eq!(
        serialized.max_network_requests,
        DEFAULT_MAX_NETWORK_REQUESTS
    );
    assert_eq!(serialized.max_redirect_hops, DEFAULT_MAX_REDIRECT_HOPS);
    assert_eq!(
        serialized.max_acquisition_seconds,
        DEFAULT_MAX_ACQUISITION_SECONDS
    );
    let value = serde_json::to_value(serialized).unwrap();
    assert_eq!(value["max_network_requests"], DEFAULT_MAX_NETWORK_REQUESTS);
    assert_eq!(value["max_redirect_hops"], DEFAULT_MAX_REDIRECT_HOPS);
    assert_eq!(
        value["max_acquisition_seconds"],
        DEFAULT_MAX_ACQUISITION_SECONDS
    );
}

#[test]
fn defaults_keep_untrusted_traversal_and_source_reads_conservative() {
    let limits = EngineLimits::default();

    assert_eq!(limits.max_packages, DEFAULT_MAX_PACKAGES);
    assert_eq!(limits.max_source_file_size, DEFAULT_MAX_SOURCE_FILE_SIZE);
}

#[test]
fn report_schema_declares_every_serialized_limit() {
    let limits = serde_json::to_value(SerializableLimits::from(&EngineLimits::default())).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/schema/report.schema.json")).unwrap();
    let limit_schema = &schema["$defs"]["limits"];
    let properties = limit_schema["properties"].as_object().unwrap();
    let required = limit_schema["required"].as_array().unwrap();

    for field in limits.as_object().unwrap().keys() {
        assert!(properties.contains_key(field), "schema is missing {field}");
        assert!(
            required.iter().any(|required| required == field),
            "schema does not require always-serialized field {field}"
        );
    }
}
