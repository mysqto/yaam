//! A rebuild through the built binary, over a store whose timelines have rolled over twice.
//!
//! `yaam reindex --all` re-enqueues fan-out for every record in the tree, so every append runs a
//! second time. That is the common way a record already listed in a timeline gets listed again, and
//! it is why the check on append cannot be a look at the newest files: two rollovers on, the line
//! is frozen in a part that no bounded read of the timeline reaches.
//!
//! In process rather than through a running service, but through the real `yaam` binary for the
//! rebuild itself: the rebuild is an operator action, and what it does to the tree is the half a
//! library test would not see.

#![forbid(unsafe_code)]

use std::fs;

use yaam_core::Pipeline;

mod support;

use support::{BODY, Deployment, index_of, record, timeline_mentions, yaam};

/// The entity the fixture record names, and whose timeline the fan-out materialises.
const ENTITY: (&str, &str) = ("ticket", "PROJ-42");

#[test]
fn a_rebuild_past_two_rollovers_leaves_the_record_listed_once() {
    let deployment = Deployment::new();
    let record = record();
    let id = record.record_id.clone();
    {
        let mut pipeline = Pipeline::new(deployment.root()).expect("pipeline");
        pipeline.accept(record, BODY).expect("accepted");
        assert_eq!(pipeline.drain_fanout(10).expect("drained"), 1);
    }
    let timeline = deployment.timeline_dir(ENTITY.0, ENTITY.1);
    assert_eq!(timeline_mentions(&timeline, &id), 1);
    assert_eq!(mention_rows(&deployment), 1);

    // Two rollovers after that append: the record's line is in a part that is no longer the newest,
    // which is the state the old check answered wrongly. Written by hand because reaching it
    // through the service would mean two thousand records for a property three files state.
    let head = timeline.join("timeline.md");
    fs::rename(&head, timeline.join("timeline-0001.md")).expect("freeze");
    fs::write(timeline.join("timeline-0002.md"), "- older history\n").expect("a later part");
    fs::write(&head, "").expect("a fresh head");

    let rebuilt = yaam(&["--root", deployment.root_str(), "reindex", "--all"]);
    assert_eq!(
        rebuilt.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    let said = String::from_utf8_lossy(&rebuilt.stdout);
    assert!(said.contains("timelines dropped   3"), "{said}");

    // Files and rows went together. Either one surviving the other is a duplicate or a line nothing
    // will write again, so this is asserted rather than left to the count below.
    assert_eq!(timeline_mentions(&timeline, &id), 0, "the files are gone");
    assert!(!timeline.join("timeline-0001.md").exists());
    assert_eq!(mention_rows(&deployment), 0, "and so are the rows");

    {
        let mut pipeline = Pipeline::new(deployment.root()).expect("pipeline");
        assert_eq!(pipeline.drain_fanout(10).expect("drained"), 1);
    }
    assert_eq!(
        timeline_mentions(&timeline, &id),
        1,
        "the record is listed twice; the head holds {:?}",
        fs::read_to_string(&head)
    );
    assert_eq!(
        fs::read_to_string(&head).expect("head").lines().count(),
        1,
        "the timeline was rebuilt, not appended to beside the parts it replaced"
    );
    assert_eq!(mention_rows(&deployment), 1);
}

/// Rows in the index accounting for the lines of every timeline.
fn mention_rows(deployment: &Deployment) -> i64 {
    index_of(deployment)
        .query_row("SELECT COUNT(*) FROM timeline_mentions", [], |row| {
            row.get(0)
        })
        .expect("count")
}
