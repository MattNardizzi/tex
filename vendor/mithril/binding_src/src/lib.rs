// PyO3 binding for the threshold-ml-dsa Rust crate (Mithril, ePrint 2026/013).
// Produces bit-for-bit FIPS 204 signatures from a t-of-n threshold quorum.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::OsRng;
use threshold_ml_dsa::sdk::ThresholdMlDsa44Sdk;

/// Python wrapper for ThresholdMlDsa44Sdk.
///
/// Mithril threshold ML-DSA-44 (FIPS 204) per ePrint 2026/013.
/// Output signatures are bit-for-bit verifiable by any standard ML-DSA-44 verifier.
#[pyclass]
struct MithrilSdk {
    inner: ThresholdMlDsa44Sdk,
}

#[pymethods]
impl MithrilSdk {
    /// Create a fresh threshold key set from a 32-byte seed.
    ///
    /// In production use OsRng to fill the seed; this constructor is
    /// deterministic for testing.
    #[new]
    fn new(seed: &[u8], t: u8, n: u8, max_retries: usize) -> PyResult<Self> {
        if seed.len() != 32 {
            return Err(PyValueError::new_err(
                format!("seed must be 32 bytes, got {}", seed.len()),
            ));
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed);
        let inner = ThresholdMlDsa44Sdk::from_seed(&seed_arr, t, n, max_retries)
            .map_err(|e| PyRuntimeError::new_err(format!("Mithril keygen failed: {:?}", e)))?;
        Ok(MithrilSdk { inner })
    }

    /// Return the packed FIPS 204 public key.
    fn public_key<'py>(&self, py: Python<'py>) -> &'py PyBytes {
        PyBytes::new(py, self.inner.pk())
    }

    /// Number of parties (N) in the threshold scheme.
    fn num_parties(&self) -> usize {
        self.inner.num_parties()
    }

    /// Sign `msg` under the t-of-n threshold with the parties in `active`.
    ///
    /// `active` must be a sorted, strictly-ascending list of party indices
    /// of length exactly t. Output is a bit-for-bit FIPS 204 signature.
    fn threshold_sign<'py>(
        &self,
        py: Python<'py>,
        active: Vec<u8>,
        msg: &[u8],
    ) -> PyResult<&'py PyBytes> {
        let mut rng = OsRng;
        let sig = self
            .inner
            .threshold_sign(&active, msg, &mut rng)
            .map_err(|e| PyRuntimeError::new_err(format!("threshold sign failed: {:?}", e)))?;
        Ok(PyBytes::new(py, &sig))
    }

    /// Verify a FIPS 204 signature under this SDK's public key.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.inner.verify(msg, sig)
    }
}

/// Standalone FIPS 204 verify (any ML-DSA-44 verifier can do this — we
/// expose it so the Python side can verify against a public key bytes
/// that was produced elsewhere).
#[pyfunction]
fn verify_fips204(pk: &[u8], msg: &[u8], sig: &[u8]) -> PyResult<bool> {
    // The dilithium-rs crate provides the underlying verifier; we route
    // through it. The Mithril crate's `verify` method uses dilithium-rs
    // internally, so this is the same code path.
    use threshold_ml_dsa::verify;
    Ok(verify::verify(sig, msg, pk))
}

#[pymodule]
fn tex_mithril(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<MithrilSdk>()?;
    m.add_function(wrap_pyfunction!(verify_fips204, m)?)?;
    Ok(())
}
