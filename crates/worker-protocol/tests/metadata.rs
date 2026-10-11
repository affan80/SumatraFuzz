use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use uuid::Uuid;
use worker_protocol::{ControllerId, RunId, WorkerId};

fn assert_json_roundtrip<T>(value: T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let json = serde_json::to_string(&value).expect("serialize opaque identifier");
    let restored: T = serde_json::from_str(&json).expect("deserialize opaque identifier");
    assert_eq!(restored, value);
}

#[test]
fn identifiers_round_trip_without_loss() {
    let id = Uuid::from_u128(0x49cd6b2abff14fdd8ca0c03a224fc901);
    assert_json_roundtrip(RunId(id));
    assert_json_roundtrip(WorkerId(id));
    assert_json_roundtrip(ControllerId(id));
}

#[test]
fn identifiers_reject_invalid_uuid_strings() {
    for bad in ["not-a-uuid", "", "123", "[]"] {
        let encoded = serde_json::to_string(bad).expect("encode test input");
        assert!(serde_json::from_str::<RunId>(&encoded).is_err(), "{bad}");
        assert!(serde_json::from_str::<WorkerId>(&encoded).is_err(), "{bad}");
        assert!(serde_json::from_str::<ControllerId>(&encoded).is_err(), "{bad}");
    }
}

#[test]
fn identifiers_are_json_strings_not_exposed_struct_fields() {
    let id = Uuid::from_u128(0x00000000000000000000000000000001);
    let json = serde_json::to_string(&RunId(id)).expect("serialize run ID");
    assert_eq!(json, "\"00000000-0000-0000-0000-000000000001\"");
}
