use super::{EngineLimits, SerializableLimits};

#[test]
fn serializable_limits_include_network_acquisition_bounds() {
    let limits = EngineLimits::default();
    let serialized = SerializableLimits::from(&limits);

    assert_eq!(serialized.max_network_requests, 1_000);
    assert_eq!(serialized.max_acquisition_seconds, 300);
    let value = serde_json::to_value(serialized).unwrap();
    assert_eq!(value["max_network_requests"], 1_000);
    assert_eq!(value["max_acquisition_seconds"], 300);
}
