use keri::prefix::Prefix;
use runar_keri::{RunarKeriCore, RunarKeriService};
use tempfile::TempDir;

#[tokio::test]
async fn test_create_user_identity() {
    // create temp directory for sled
    let tmp_dir = TempDir::new().expect("tmp");
    let db_path = tmp_dir.path().to_str().unwrap();

    // init core
    let mut core = RunarKeriCore::new(db_path).await.expect("init");

    // create identity
    let aid = core.create_user_identity().await.expect("create aid");
    assert!(!aid.to_str().is_empty());

    // verify state stored
    let state = core.compute_state(&aid).expect("state").expect("some");
    assert_eq!(state.sn, 0);
    assert_eq!(state.prefix, aid);
}
