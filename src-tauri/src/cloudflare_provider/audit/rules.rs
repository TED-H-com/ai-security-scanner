use super::{record::*, *};
pub(crate) fn issue(
    record: &Record,
    requested: &[AssignmentSpec],
    profile: Profile,
    budget: Option<u64>,
) -> Result<Content, Refusal> {
    use Refusal::*;
    use Role::*;
    if requested.is_empty() || requested.len() > 64 {
        return Err(AssignmentBatchLimit);
    }
    if record.assignments.len() + requested.len() > 2000 {
        return Err(AssignmentRunLimit);
    }
    let mut state = record.assignments.clone();
    let mut issued = Vec::new();
    for spec in requested {
        let wave_role = matches!(spec.role, Hunter | PostWaveCritic);
        if wave_role != spec.wave.is_some()
            || spec.wave == Some(0)
            || matches!(spec.role, CandidateVerifier | FinalVerifier) != spec.fingerprint.is_some()
        {
            return Err(RoleFieldsInvalid);
        }
        if let Some(f) = &spec.fingerprint
            && (f.len() > 4096
                || !f.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                || !f
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:/@+-".contains(&b)))
        {
            return Err(FingerprintInvalid);
        }
        let highest = state
            .iter()
            .filter(|a| a.assignment.spec.role == Hunter)
            .filter_map(|a| a.assignment.spec.wave)
            .max()
            .unwrap_or(0);
        let quick = matches!(profile, Profile::Quick);
        if spec.role == FinalVerifier && quick {
            return Err(QuickFinalVerifierUnavailable);
        }
        if spec.role == FinalCleanCritic && quick {
            return Err(QuickFinalCleanUnavailable);
        }
        if spec.role == Hunter {
            let wave = spec.wave.unwrap();
            if quick && wave != 1 {
                return Err(QuickWaveLimit);
            }
            if wave > highest.saturating_add(1) {
                return Err(WaveSkipped);
            }
            if state.iter().any(|a| {
                a.assignment.spec.role == PostWaveCritic && a.assignment.spec.wave == spec.wave
            }) {
                return Err(WaveClosed);
            }
        }
        if spec.role == PostWaveCritic
            && !state
                .iter()
                .any(|a| a.assignment.spec.role == Hunter && a.assignment.spec.wave == spec.wave)
        {
            return Err(CriticRequiresHunters);
        }
        let id = crate::domain::new_id();
        if let Some(replaces) = &spec.replaces {
            let old = state
                .iter_mut()
                .find(|a| a.assignment.assignment_id == *replaces)
                .ok_or(UnknownAssignment)?;
            if !matches!(old.state, "interrupted" | "discarded") {
                return Err(ReplacementNotInterrupted);
            }
            if old.replaced_by.is_some() {
                return Err(AssignmentAlreadyReplaced);
            }
            if old.assignment.spec.role != spec.role
                || old.assignment.spec.wave != spec.wave
                || old.assignment.spec.fingerprint != spec.fingerprint
            {
                return Err(ReplacementMismatch);
            }
            old.replaced_by = Some(id.clone());
        }
        let ordinal = state.len() as u64 + 1;
        let a = Assignment {
            assignment_id: id,
            agent_id: format!("a{ordinal:04}-{}", spec.role.word()),
            ordinal,
            issued_at: String::new(),
            spec: spec.clone(),
            findings_revision: None,
            bound_record_sha256: None,
        };
        state.push(AssignmentState {
            assignment: a.clone(),
            state: "open",
            closed_at: None,
            output: None,
            interruption_reason: None,
            replaced_by: None,
        });
        issued.push(a);
    }
    if let Some(limit) = budget {
        if state.len() as u64 > limit {
            return Err(InvocationBudgetExhausted);
        }
        if requested
            .iter()
            .any(|a| matches!(a.role, Hunter | ReconnaissanceFocused))
            && limit - (state.len() as u64) < owed(&state, profile)
        {
            return Err(BudgetCannotReserveCriticsAndValidation);
        }
    }
    Ok(Content::Issue {
        assignments: issued,
    })
}
pub(crate) fn owed(state: &[AssignmentState], profile: Profile) -> u64 {
    use Role::*;
    let active: Vec<_> = state
        .iter()
        .filter(|a| !matches!(a.state, "interrupted" | "discarded"))
        .map(|a| &a.assignment.spec)
        .collect();
    let has = |role| active.iter().any(|a| a.role == role);
    let highest = active
        .iter()
        .filter(|a| a.role == Hunter)
        .filter_map(|a| a.wave)
        .max();
    let critic = if matches!(profile, Profile::Quick) {
        has(PostWaveCritic)
    } else {
        highest.is_some()
            && active
                .iter()
                .any(|a| a.role == PostWaveCritic && a.wave == highest)
    };
    4u64.saturating_sub(
        active
            .iter()
            .filter(|a| a.role == ReconnaissanceBaseline)
            .count() as u64,
    ) + u64::from(!has(CandidateVerifier))
        + u64::from(!critic)
        + u64::from(!matches!(profile, Profile::Quick) && !has(FinalCleanCritic))
}
pub(crate) fn interrupt(
    record: &Record,
    assignment_id: &str,
    reason: &str,
) -> Result<Content, Refusal> {
    if reason.is_empty() || reason.len() > 512 || reason.chars().any(char::is_control) {
        return Err(Refusal::InterruptionReasonInvalid);
    }
    let a = record
        .assignments
        .iter()
        .find(|a| a.assignment.assignment_id == assignment_id)
        .ok_or(Refusal::UnknownAssignment)?;
    if a.state != "open" {
        return Err(Refusal::AssignmentClosed);
    }
    Ok(Content::Interrupt {
        assignment_id: assignment_id.into(),
        reason: reason.into(),
    })
}
#[cfg(test)]
mod tests;
