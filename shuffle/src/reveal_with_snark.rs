use std::{borrow::Borrow, marker::PhantomData};

use ark_ec::{CurveConfig, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective};
use ark_ff::{BitIteratorLE, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    groups::{CurveVar, GroupOpsBounds},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};

use crate::{
    keygen::{Keypair, SecretKey},
    MaskedCard, RevealCard,
};

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct RevealParameters<C: CurveGroup> {
    g: C::Affine,
    h: C::Affine,
    reveal: C::Affine,
    pk: C::Affine,
    sk: <<C as CurveGroup>::Config as CurveConfig>::ScalarField,
}

#[derive(Clone)]
pub struct RevealVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    g: GC,
    h: GC,
    reveal: GC,
    pk: GC,
    sk: Vec<Boolean<ConstraintF<C>>>,
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
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let g = GC::new_variable(cs.clone(), || Ok(val.borrow().g), AllocationMode::Constant)?;
            let h = GC::new_variable(cs.clone(), || Ok(val.borrow().h), AllocationMode::Input)?;
            let reveal = GC::new_variable(
                cs.clone(),
                || Ok(val.borrow().reveal),
                AllocationMode::Input,
            )?;
            let pk = GC::new_variable(cs.clone(), || Ok(val.borrow().pk), AllocationMode::Input)?;

            let bits = BitIteratorLE::new(val.borrow().sk.into_bigint()).collect::<Vec<_>>();
            let sk: Vec<Boolean<ConstraintF<C>>> = AllocVar::new_variable(
                cs.clone(),
                || Ok(bits.as_slice()),
                AllocationMode::Witness,
            )?;

            Ok(Self {
                g,
                h,
                reveal,
                pk,
                sk,
                _curve: PhantomData,
            })
        })
    }
}

#[derive(Clone)]
pub struct RevealCircuit<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>> {
    params: RevealParameters<C>,
    _group: PhantomData<*const GC>,
}

impl RevealCircuit<EdwardsProjective, EdwardsVar> {
    pub fn new(sk: &SecretKey, masked_card: &MaskedCard, reveal_card: &RevealCard) -> Self {
        let keypair = Keypair::from_secret(*sk);
        let g = EdwardsProjective::generator();

        let params = RevealParameters::<EdwardsProjective> {
            h: masked_card.e1.into_affine(),
            g: g.into_affine(),
            reveal: reveal_card.into_affine(),
            pk: keypair.public.into_affine(),
            sk: *sk,
        };

        Self {
            params,
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
            RevealVar::new_input(ark_relations::ns!(cs, "parameters"), || Ok(self.params))?;

        let tmp1: GC = params_var
            .g
            .scalar_mul_le(params_var.sk.to_bits_le()?.iter())?;
        tmp1.enforce_equal(&params_var.pk)?;

        let tmp2 = params_var
            .h
            .scalar_mul_le(params_var.sk.to_bits_le()?.iter())?;
        tmp2.enforce_equal(&params_var.reveal)
    }
}
