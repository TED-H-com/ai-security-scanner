use super::*;
fn spec(role: Role) -> AssignmentSpec {
    AssignmentSpec {
        role,
        wave: (role == Role::Hunter).then_some(1),
        fingerprint: (role == Role::CandidateVerifier).then(|| "CVE:example".into()),
        replaces: None,
    }
}
fn record(roles: &[Role]) -> Record {
    Record {
        assignments: roles
            .iter()
            .map(|role| AssignmentState {
                assignment: Assignment {
                    assignment_id: crate::domain::new_id(),
                    agent_id: String::new(),
                    ordinal: 0,
                    issued_at: String::new(),
                    findings_revision: None,
                    bound_record_sha256: None,
                    spec: spec(*role),
                },
                state: "open",
                closed_at: None,
                output: None,
                interruption_reason: None,
                replaced_by: None,
            })
            .collect(),
        ..Record::default()
    }
}
#[test]
fn arithmetic_floors_reserves_null_and_interruption() {
    use Role::*;
    assert_eq!(owed(&[], Profile::Quick), 6);
    assert_eq!(owed(&[], Profile::Standard), 7);
    assert_eq!(owed(&[], Profile::Deep), 7);
    let baseline = record(&[ReconnaissanceBaseline; 4]);
    for (profile, no, yes) in [
        (Profile::Quick, 6, 7),
        (Profile::Standard, 7, 8),
        (Profile::Deep, 7, 8),
    ] {
        assert_eq!(
            issue(&baseline, &[spec(Hunter)], profile, Some(no)).unwrap_err(),
            Refusal::BudgetCannotReserveCriticsAndValidation
        );
        assert!(issue(&baseline, &[spec(Hunter)], profile, Some(yes)).is_ok());
        assert!(issue(&baseline, &[spec(Hunter)], profile, None).is_ok());
    }
    assert_eq!(
        issue(
            &Record::default(),
            &[spec(ReconnaissanceFocused)],
            Profile::Quick,
            Some(6)
        )
        .unwrap_err(),
        Refusal::BudgetCannotReserveCriticsAndValidation
    );
    assert!(
        issue(
            &Record::default(),
            &[spec(ReconnaissanceFocused)],
            Profile::Quick,
            Some(7)
        )
        .is_ok()
    );
    let mut r = record(&[
        ReconnaissanceBaseline,
        ReconnaissanceBaseline,
        ReconnaissanceBaseline,
        ReconnaissanceBaseline,
        CandidateVerifier,
    ]);
    assert!(issue(&r, &[spec(Hunter)], Profile::Quick, Some(7)).is_ok());
    r.assignments[4].state = "interrupted";
    assert_eq!(
        issue(&r, &[spec(Hunter)], Profile::Quick, Some(7)).unwrap_err(),
        Refusal::BudgetCannotReserveCriticsAndValidation
    );
    assert_eq!(
        issue(
            &r,
            &[spec(ReconnaissanceBaseline); 1],
            Profile::Quick,
            Some(5)
        )
        .unwrap_err(),
        Refusal::InvocationBudgetExhausted
    );
    // This request itself discharges all reserves, including its final critic.
    let mut all = vec![spec(ReconnaissanceBaseline); 4];
    all.extend([
        spec(Hunter),
        spec(CandidateVerifier),
        AssignmentSpec {
            role: PostWaveCritic,
            wave: Some(1),
            fingerprint: None,
            replaces: None,
        },
    ]);
    assert!(issue(&Record::default(), &all, Profile::Quick, Some(7)).is_ok());
}
#[test]
fn owed_uses_latest_active_wave_and_ignores_interrupted_reserves() {
    use Role::*;
    let mut r = record(&[
        ReconnaissanceBaseline,
        ReconnaissanceBaseline,
        ReconnaissanceBaseline,
        ReconnaissanceBaseline,
        Hunter,
        PostWaveCritic,
        FinalCleanCritic,
        CandidateVerifier,
    ]);
    r.assignments[5].assignment.spec.wave = Some(1);
    assert_eq!(owed(&r.assignments, Profile::Standard), 0);
    r.assignments[4].assignment.spec.wave = Some(2);
    assert_eq!(owed(&r.assignments, Profile::Standard), 1);
    assert_eq!(owed(&r.assignments, Profile::Quick), 0);
    for index in [0, 5, 6, 7] {
        r.assignments[index].state = "interrupted";
    }
    assert_eq!(owed(&r.assignments, Profile::Standard), 4);
    assert_eq!(owed(&r.assignments, Profile::Quick), 3);
}
