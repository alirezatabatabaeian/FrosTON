use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use frost_dalek::nizk::NizkOfSecretKey;
use crate::parameters::Parameters;
use std::convert::TryInto;

#[pyclass]
#[derive(Clone)]
pub struct Participant {
    pub participant: frost_dalek::keygen::Participant,
    pub coefficients: frost_dalek::keygen::Coefficients,
}

#[pymethods]
impl Participant {
    #[new]
    pub fn new(parameters: &Parameters, index: u32) -> Self {
        let (participant, coefficients) = frost_dalek::keygen::Participant::new(&parameters.parameters, index);

        Participant {
            participant: participant,
            coefficients: coefficients,
        }
    }

    pub fn verify_proof_of_secret_key(&self) -> PyResult<()> {
        match self.participant.proof_of_secret_key.verify(&self.participant.index, &self.participant.public_key().unwrap()) {
            Ok(_) => Ok(()),
            Err(_) => Err(PyValueError::new_err("errors")),
        }
    }

    pub fn encode(&self, t: u32) -> Vec<u8> {
        let mut v : Vec<u8> = Vec::new();
        let i = self.participant.index;
        let output: [u8; 4] = i.to_be_bytes();
        v.extend_from_slice(&output);
        let c = &self.participant.commitments;
        for i in 0..t {
            let r = c.get(i as usize);
            let rb = r.unwrap().compress().to_bytes();
            v.extend_from_slice(&rb);
        }
        let z = &self.participant.proof_of_secret_key;
        let zsb = z.s.to_bytes();
        v.extend_from_slice(&zsb);
        let zrb = z.r.to_bytes();
        v.extend_from_slice(&zrb);
        return v;
    }

    #[staticmethod]
    pub fn load(x: &[u8], t: u32) -> Participant {
        let mut s: usize = 0;
        let mut e: usize = 4;
        let i = u32::from_be_bytes(x[s..e].try_into().unwrap());
        let mut commitments : Vec<RistrettoPoint> = Vec::new();
        for i in 0..t {
            s = (4 + (i * 32)) as usize;
            e = s + 32;
            let rb: [u8; 32] = x[s..e].try_into().unwrap();
            let r = CompressedRistretto::from_slice(&rb).decompress();
            commitments.push(r.unwrap());
        }
        s = e;
        e = s + 32;
        let zsb: [u8; 32] = x[s..e].try_into().unwrap();
        let zs = Scalar::from_bits(zsb);
        s = e;
        e = s + 32;
        let zrb: [u8; 32] = x[s..e].try_into().unwrap();
        let zr = Scalar::from_bits(zrb);
        let k = NizkOfSecretKey{s: zs, r: zr};
        let pp = frost_dalek::Participant{
            index:i,
            proof_of_secret_key: k,
            commitments: commitments,
        };
        let mut coeffs : Vec<Scalar> = Vec::new();
        for i in 0..t{
            coeffs.push(Scalar::zero());
        }
        Participant {
            participant: pp,
            coefficients: frost_dalek::keygen::construct_coeffs(coeffs)
        }
    }
}