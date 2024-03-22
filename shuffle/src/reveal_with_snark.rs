use std::{borrow::Borrow, marker::PhantomData};

use ark_ec::{CurveConfig, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fr};
use ark_ff::{BigInteger, BitIteratorLE, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{CurveVar, GroupOpsBounds},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};

use crate::{keygen::PublicKey, MaskedCard, RevealCard};
use uzkge::{
    chaum_pedersen::dl::ChaumPedersenDLProof as ZChaumPedersenDLProof, poly_commit::pcs::ToBytes,
    utils::transcript::Transcript,
};

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ChaumPedersenDLParameters<C: CurveGroup> {
    g: C::Affine,
    h: C::Affine,
}

#[derive(Clone)]
pub struct ChaumPedersenDLParametersVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    g: GC,
    h: GC,
    _curve: PhantomData<C>,
}

impl<C, GC> AllocVar<ChaumPedersenDLParameters<C>, ConstraintF<C>>
    for ChaumPedersenDLParametersVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<ChaumPedersenDLParameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let g = GC::new_variable(cs.clone(), || Ok(val.borrow().g), AllocationMode::Constant)?;
            let h = GC::new_variable(cs, || Ok(val.borrow().h), AllocationMode::Input)?;
            Ok(Self {
                g,
                h,
                _curve: PhantomData,
            })
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ChaumPedersenDLProof<C: CurveGroup> {
    a: C::Affine,
    b: C::Affine,
    r: <<C as CurveGroup>::Config as CurveConfig>::ScalarField,
}

#[derive(Clone)]
pub struct ChaumPedersenDLProofVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    a: GC,
    b: GC,
    r: Vec<Boolean<ConstraintF<C>>>,
    _curve: PhantomData<C>,
}

impl<C, GC> AllocVar<ChaumPedersenDLProof<C>, ConstraintF<C>> for ChaumPedersenDLProofVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<ChaumPedersenDLProof<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let a = GC::new_variable(cs.clone(), || Ok(val.borrow().a), mode)?;
            let b = GC::new_variable(cs.clone(), || Ok(val.borrow().b), mode)?;

            let bits = BitIteratorLE::new(val.borrow().r.into_bigint()).collect::<Vec<_>>();
            let r: Vec<Boolean<ConstraintF<C>>> =
                AllocVar::new_variable(cs.clone(), || Ok(bits.as_slice()), mode)?;

            Ok(Self {
                a,
                b,
                r,
                _curve: PhantomData,
            })
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct RevealParameters<C: CurveGroup> {
    reveal_card: C::Affine,
    pk: C::Affine,
    pub challenge: <<C as CurveGroup>::Config as CurveConfig>::ScalarField,
}

#[derive(Clone)]
pub struct RevealVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    reveal_card: GC,
    pk: GC,
    challenge: Vec<Boolean<ConstraintF<C>>>,
    _curve: PhantomData<C>,
}

impl<C, GC> AllocVar<RevealParameters<C>, ConstraintF<C>> for RevealVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<RevealParameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let reveal_card = GC::new_variable(cs.clone(), || Ok(val.borrow().reveal_card), mode)?;
            let pk = GC::new_variable(cs.clone(), || Ok(val.borrow().pk), mode)?;

            let challenge_bytes = val.borrow().challenge.into_bigint().to_bytes_le();
            let challenge_big = ConstraintF::<C>::from_le_bytes_mod_order(&challenge_bytes);
            let bits = BitIteratorLE::new(val.borrow().challenge.into_bigint()).collect::<Vec<_>>();
            let bits: Vec<Boolean<ConstraintF<C>>> = AllocVar::new_variable(
                cs.clone(),
                || Ok(bits.as_slice()),
                AllocationMode::Witness,
            )?;
            let f: FpVar<ConstraintF<C>> =
                AllocVar::new_variable(cs.clone(), || Ok(challenge_big), mode)?;
            let claimed_f = Boolean::le_bits_to_fp(&bits)?;
            claimed_f.enforce_equal(&f)?;

            Ok(Self {
                reveal_card,
                pk,
                challenge: bits,
                _curve: PhantomData,
            })
        })
    }
}

#[derive(Clone)]
pub struct RevealCircuit<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>> {
    params: ChaumPedersenDLParameters<C>,
    proof: ChaumPedersenDLProof<C>,
    pub reveal: RevealParameters<C>,
    _group: PhantomData<*const GC>,
}

impl RevealCircuit<EdwardsProjective, EdwardsVar> {
    pub fn new(
        pk: &PublicKey,
        masked_card: &MaskedCard,
        reveal_card: &RevealCard,
        proof: &ZChaumPedersenDLProof,
    ) -> Self {
        let g = EdwardsProjective::generator();

        let mut transcript = Transcript::new(b"Revealing");
        transcript.append_message(b"Chaum Pedersen", b"DL");
        transcript.append_message(b"append commitment", &masked_card.e1.to_transcript_bytes());
        transcript.append_message(b"append commitment", &g.to_transcript_bytes());
        transcript.append_message(b"append commitment", &reveal_card.to_transcript_bytes());
        transcript.append_message(b"append commitment", &pk.to_transcript_bytes());

        transcript.append_message(b"append commitment", &proof.a.to_transcript_bytes());
        transcript.append_message(b"append commitment", &proof.b.to_transcript_bytes());

        let c: Fr = transcript.get_challenge_field_elem(b"Chaum Pedersen C");

        let params = ChaumPedersenDLParameters::<EdwardsProjective> {
            h: masked_card.e1.into_affine(),
            g: g.into_affine(),
        };

        let proof = ChaumPedersenDLProof::<EdwardsProjective> {
            a: proof.a.into_affine(),
            b: proof.b.into_affine(),
            r: proof.r,
        };

        let reveal = RevealParameters::<EdwardsProjective> {
            reveal_card: reveal_card.into_affine(),
            pk: pk.into_affine(),
            challenge: c,
        };

        Self {
            params,
            proof,
            reveal,
            _group: PhantomData,
        }
    }
}

impl<C, GC> ConstraintSynthesizer<ConstraintF<C>> for RevealCircuit<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        let params_var =
            ChaumPedersenDLParametersVar::new_input(ark_relations::ns!(cs, "parameters"), || {
                Ok(self.params)
            })?;
        let proof_var =
            ChaumPedersenDLProofVar::new_witness(ark_relations::ns!(cs, "proof"), || {
                Ok(self.proof)
            })?;
        let reveal_var = RevealVar::new_input(ark_relations::ns!(cs, "proof"), || Ok(self.reveal))?;

        let tmp1 = params_var
            .h
            .scalar_mul_le(proof_var.r.to_bits_le()?.iter())?;
        let tmp2 = reveal_var
            .reveal_card
            .scalar_mul_le(reveal_var.challenge.to_bits_le()?.iter())?;
        let tmp3 = tmp2.add(&proof_var.a);
        tmp1.enforce_equal(&tmp3)?;

        let tmp1 = params_var
            .g
            .scalar_mul_le(proof_var.r.to_bits_le()?.iter())?;
        let tmp2 = reveal_var
            .pk
            .scalar_mul_le(reveal_var.challenge.to_bits_le()?.iter())?;
        let tmp3 = tmp2.add(proof_var.b);
        tmp1.enforce_equal(&tmp3)
    }
}
