use super::*;

fn call<S: OperationStore>(ctx: &ApiContext<'_, S>, method: &str, params: &str) -> Json {
    let line =
        format!("{{\"v\":1,\"request_id\":\"o\",\"method\":\"{method}\",\"params\":{params}}}");
    routeloom_json::parse(&handle(line.as_bytes(), ctx)).unwrap()
}
fn code(doc: &Json) -> Option<&str> {
    doc.get("error")?.get("code")?.as_str()
}

#[test]
fn objects_admission_identity_and_cancel() {
    let (acl, log, store, limiter) = tests::test_env();
    let ops = crate::objects::ObjectOps::with_boot(17);
    let c = ApiContext {
        object_ops: &ops,
        ..tests::ctx(Some(501), &acl, &log, &store, &limiter, 0)
    };
    let params = "{\"network\":\"0000000000000001\",\"node\":\"0000000000000002\",\"data\":\"AQ==\",\"key\":\"01010101010101010101010101010101\"}";
    assert_eq!(
        code(&call(&c, "objects.submit", params)),
        Some("GATEWAY_UNAVAILABLE")
    );
    {
        let mut session = c.session.lock().unwrap();
        session.authenticated = true;
        session.network = Some(1);
        session.capability = Some(0);
    }
    assert_eq!(
        code(&call(&c, "objects.submit", params)),
        Some("UNSUPPORTED")
    );
    c.session.lock().unwrap().capability = Some(crate::objects::CAP);
    let caps = call(&c, "capabilities.get", "{}");
    assert_eq!(
        caps.get("result")
            .unwrap()
            .get("objects")
            .unwrap()
            .get("max_object_bytes")
            .unwrap()
            .as_u64(),
        Some(4096)
    );
    let admitted = call(&c, "objects.submit", params);
    let token = admitted
        .get("result")
        .unwrap()
        .get("object_id")
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(token, "000000000000001100000001");
    c.session.lock().unwrap().authenticated = false;
    let caps = call(&c, "capabilities.get", "{}");
    assert_eq!(
        caps.get("result")
            .unwrap()
            .get("objects")
            .unwrap()
            .get("max_object_bytes")
            .unwrap()
            .as_u64(),
        Some(0)
    );
    assert_eq!(call(&c, "objects.submit", params), admitted);
    assert_eq!(
        code(&call(&c, "objects.submit", &params.replace("AQ==", "Ag=="))),
        Some("IDEMPOTENCY_CONFLICT")
    );
    let query = format!("{{\"object_id\":\"{token}\"}}");
    let cancelled = call(&c, "objects.cancel", &query);
    assert_eq!(
        cancelled
            .get("result")
            .unwrap()
            .get("state")
            .unwrap()
            .as_str(),
        Some("CANCELLED_BEFORE_TX")
    );
    assert_eq!(
        call(&c, "objects.get", &query).get("result"),
        cancelled.get("result")
    );
    let other = ApiContext {
        principal: Some(routeloom_peercred::Principal::UnixUid(7)),
        ..c
    };
    assert_eq!(
        code(&call(&other, "objects.get", &query)),
        Some("NOT_FOUND")
    );
}

#[test]
fn object_subscription_uses_separate_cursor_and_payload_bound() {
    let (acl, log, store, limiter) = tests::test_env();
    let c = tests::ctx(Some(501), &acl, &log, &store, &limiter, 0);
    let ingress = || crate::receive_log::Ingress {
        network: 1,
        gateway: Some(2),
        origin: 3,
        msg_session: 4,
        msg_seq: 5,
        payload: vec![0x93; 4096],
        assurance: None,
    };
    assert!(matches!(
        log.lock().unwrap().ingest(ingress(), 0),
        IngestOutcome::RejectedOversize
    ));
    assert!(matches!(
        c.object_log
            .lock()
            .unwrap()
            .ingest_object(ingress(), 7, 0, 0),
        IngestOutcome::Stored { .. }
    ));
    let subscription = call(
        &c,
        "messages.subscribe",
        "{\"stream\":\"objects\",\"from\":\"latest\",\"network\":\"0000000000000001\",\"payloads\":false}",
    );
    assert!(code(&subscription).is_none(), "{subscription:?}");
    assert_eq!(
        subscription
            .get("result")
            .unwrap()
            .get("stream")
            .unwrap()
            .as_str(),
        Some("objects")
    );
    assert_ne!(
        c.object_log.lock().unwrap().epoch(),
        log.lock().unwrap().epoch()
    );
    let denied = call(
        &c,
        "messages.subscribe",
        "{\"stream\":\"objects\",\"from\":\"latest\",\"network\":\"0000000000000001\",\"payloads\":true}",
    );
    assert_eq!(code(&denied), Some("AuthorizationFailed"));
}
