//! Compatibility entry points and dispatch for the historical circuits.
use super::*;

/// Calcola l'identificazione privata esatta e la soglia associata soltanto al vincitore.
///
/// `packed_probe` contiene il probe a `Delta=2^52` nei coefficienti 0..511 e lo stesso probe
/// modulo16 a `Delta=2^60` nei coefficienti 1024..1535. Il server possiede la galleria in chiaro
/// e una chiave di valutazione, ma non la chiave segreta. L'unico ciphertext restituito codifica
/// `0=rifiuto` oppure `indice+1=match`.
///
/// Il client deve aver validato prima della cifratura coordinate in `[-3,3]` e norma quadrata
/// non superiore a [`PROBE_NORM2_MAX`]. Il dominio fornito prova la correttezza sotto quel vincolo;
/// il server non puo' ricontrollare in chiaro una proprieta' del probe cifrato.
pub fn private_argmin(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<PrivateArgminOutput, PrivateArgminError> {
    private_argmin_impl(server_key, packed_probe, templates, domain, None)
}

/// Calcola l'identificazione privata esatta A41 con due cifre terminali p16 separate.
///
/// Questa API e' intenzionalmente fail-closed: accetta soltanto il percorso uniforme allineato
/// A38. Il client decifra le due cifre e ricostruisce `low_nibble + 16 * high_nibble`, ottenendo
/// `0=rifiuto` oppure `indice+1=match`, con tie risolti sulla prima identita'.
pub fn private_argmin_two_lwe(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<PrivateArgminTwoLweOutput, PrivateArgminError> {
    private_argmin_two_lwe_impl(server_key, packed_probe, templates, domain, None)
}

/// Endpoint pubblico A44. Prima di entrare nel grafo A41 verifica sia l'identita' protocollare
/// dichiarata dalla richiesta sia tutta la geometria ricostruibile dalla server key. La risposta
/// ripete il binding canonico, che il client deve verificare prima di decifrare.
pub fn private_argmin_two_lwe_a44(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<A44PrivateArgminTwoLweOutput, PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let output = private_argmin_two_lwe_impl(server_key, packed_probe, templates, domain, None)?;
    Ok(A44PrivateArgminTwoLweOutput {
        low_nibble: output.low_nibble,
        high_nibble: output.high_nibble,
        metrics: output.metrics,
        parameter_binding: A44_PARAMETER_BINDING,
    })
}

/// Endpoint A62 integrato. A44 produce i bit e A34-top; A50 restringe il mask candidato cifrato;
/// A53 restituisce due radici p16 base-15. Il server non le ricompone: soltanto il client calcola
/// `low_digit + 15 * high_digit` dopo la decifratura.
pub fn private_argmin_a62(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<A62PrivateArgminOutput, PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let output = private_argmin_a62_impl(server_key, packed_probe, templates, domain, None)?;
    Ok(A62PrivateArgminOutput {
        low_digit: output.low_nibble,
        high_digit: output.high_nibble,
        metrics: output.metrics,
        parameter_binding: A44_PARAMETER_BINDING,
    })
}

/// Esegue lo stesso core di [`private_argmin`] conservando checkpoint cifrati per un replay locale.
///
/// Questa funzione non decifra nulla e non e' collegata al servizio o al formato wire.
#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_with_trace(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(PrivateArgminOutput, PrivateArgminTrace), PrivateArgminError> {
    let mut trace = PrivateArgminTrace::default();
    let output = private_argmin_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        Some(&mut trace),
    )?;
    Ok((output, trace))
}

/// Variante diagnostica di [`private_argmin_two_lwe`]. Non decifra alcun checkpoint.
#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_two_lwe_with_trace(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(PrivateArgminTwoLweOutput, PrivateArgminTrace), PrivateArgminError> {
    let mut trace = PrivateArgminTrace::default();
    let output = private_argmin_two_lwe_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        Some(&mut trace),
    )?;
    Ok((output, trace))
}

/// Variante diagnostica dell'endpoint A44. Il trace non modifica ne' aggira i controlli del
/// parameter binding.
#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_two_lwe_a44_with_trace(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(A44PrivateArgminTwoLweOutput, PrivateArgminTrace), PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let (output, trace) =
        private_argmin_two_lwe_with_trace(server_key, packed_probe, templates, domain)?;
    Ok((
        A44PrivateArgminTwoLweOutput {
            low_nibble: output.low_nibble,
            high_nibble: output.high_nibble,
            metrics: output.metrics,
            parameter_binding: A44_PARAMETER_BINDING,
        },
        trace,
    ))
}

/// Variante diagnostica A62. Il trace contiene solo ciphertext e contatori; non decifra nulla.
#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_a62_with_trace(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(A62PrivateArgminOutput, PrivateArgminTrace), PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let mut trace = PrivateArgminTrace::default();
    let output = private_argmin_a62_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        Some(&mut trace),
    )?;
    Ok((
        A62PrivateArgminOutput {
            low_digit: output.low_nibble,
            high_digit: output.high_nibble,
            metrics: output.metrics,
            parameter_binding: A44_PARAMETER_BINDING,
        },
        trace,
    ))
}

/// A126: fuse the level3 refresh and level4 zero test; raw noise tails remain open.
pub fn private_argmin_a126(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<A62PrivateArgminOutput, PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let output = private_argmin_a126_impl(server_key, packed_probe, templates, domain, None)?;
    Ok(A62PrivateArgminOutput {
        low_digit: output.low_nibble,
        high_digit: output.high_nibble,
        metrics: output.metrics,
        parameter_binding: A44_PARAMETER_BINDING,
    })
}

#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_a126_with_trace(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(A62PrivateArgminOutput, PrivateArgminTrace), PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let mut trace = PrivateArgminTrace::default();
    let output = private_argmin_a126_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        Some(&mut trace),
    )?;
    Ok((
        A62PrivateArgminOutput {
            low_digit: output.low_nibble,
            high_digit: output.high_nibble,
            metrics: output.metrics,
            parameter_binding: A44_PARAMETER_BINDING,
        },
        trace,
    ))
}

fn private_argmin_a126_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminTwoLweOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if !aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        return Err(PrivateArgminError::A62RequiresAlignedUniformFastPath);
    }
    let output = private_argmin_aligned_a38_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        AlignedWireFormat::A53Radix15TwoP16Digits,
        true,
        trace,
    )?;
    debug_assert!(output.code.is_none());
    Ok(PrivateArgminTwoLweOutput {
        low_nibble: output.low_nibble,
        high_nibble: output.high_nibble,
        metrics: output.metrics,
    })
}

fn private_argmin_two_lwe_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminTwoLweOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if !aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        return Err(PrivateArgminError::TwoLweRequiresAlignedUniformFastPath);
    }
    let output = private_argmin_aligned_a38_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        AlignedWireFormat::TwoP16Digits,
        false,
        trace,
    )?;
    debug_assert!(output.code.is_none());
    Ok(PrivateArgminTwoLweOutput {
        low_nibble: output.low_nibble,
        high_nibble: output.high_nibble,
        metrics: output.metrics,
    })
}

fn private_argmin_a62_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminTwoLweOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if !aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        return Err(PrivateArgminError::A62RequiresAlignedUniformFastPath);
    }
    let output = private_argmin_aligned_a38_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        AlignedWireFormat::A53Radix15TwoP16Digits,
        false,
        trace,
    )?;
    debug_assert!(output.code.is_none());
    Ok(PrivateArgminTwoLweOutput {
        low_nibble: output.low_nibble,
        high_nibble: output.high_nibble,
        metrics: output.metrics,
    })
}
