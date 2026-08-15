use super::*;

#[test]
fn graph_queue_deduplicates_requested_urls() {
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let other = Url::parse("https://example.test/other.ts").unwrap();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();

    enqueue_graph_modules(
        &mut queue,
        &mut queued,
        vec![child.clone(), child.clone(), other.clone(), child],
    );

    assert_eq!(
        queue.into_iter().collect::<Vec<_>>(),
        vec![Url::parse("https://example.test/child.ts").unwrap(), other,]
    );
}

#[test]
fn graph_queue_rejects_candidates_beyond_module_limit() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let overflow = Url::parse("https://example.test/overflow.ts").unwrap();
    let mut queue = VecDeque::from([root.clone()]);
    let mut queued = HashSet::from([canonical_graph_url(&root)]);

    enqueue_graph_module(&mut queue, &mut queued, child, 2).unwrap();
    let error = enqueue_graph_module(&mut queue, &mut queued, overflow, 2).unwrap_err();

    assert!(
        matches!(error, Error::LimitExceeded { resource, limit } if resource == "Deno graph modules" && limit == 2)
    );
    assert_eq!(queue.len(), 2);
    assert_eq!(queued.len(), 2);
}
