use ark_ff::PrimeField;
use ark_std::fmt::Formatter;

/// The structure for the trace of the Anemoi-Jive sponge hash function.
#[derive(Clone)]
pub struct AnemoiVLHTrace<F: PrimeField, const N: usize, const NUM_ROUNDS: usize> {
    /// The input sequence.
    pub input: Vec<F>,
    /// The state before each permutation.
    pub before_permutation: Vec<([F; N], [F; N])>,
    /// The intermediate values for each permutation.
    pub intermediate_values_before_constant_additions:
        Vec<([[F; N]; NUM_ROUNDS], [[F; N]; NUM_ROUNDS])>,
    /// The state after each permutation.
    pub after_permutation: Vec<([F; N], [F; N])>,
    /// The output.
    pub output: F,
}

impl<F: PrimeField, const N: usize, const NUM_ROUNDS: usize> Default
    for AnemoiVLHTrace<F, N, NUM_ROUNDS>
{
    fn default() -> Self {
        Self {
            input: vec![],
            before_permutation: vec![],
            intermediate_values_before_constant_additions: vec![],
            after_permutation: vec![],
            output: F::default(),
        }
    }
}

impl<F: PrimeField, const N: usize, const NUM_ROUNDS: usize> ark_std::fmt::Debug
    for AnemoiVLHTrace<F, N, NUM_ROUNDS>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        f.write_str("input:\n")?;
        for (i, elem) in self.input.iter().enumerate() {
            f.write_fmt(format_args!("\r x[{}] = {:?}\n", i, elem))?;
        }

        let chunk_len = if self.input.len() % (2 * N - 1) == 0 {
            self.input.len() / (2 * N - 1)
        } else {
            self.input.len() / (2 * N - 1) + 1
        };

        for i in 0..chunk_len {
            f.write_fmt(format_args!("before permutation: {}\n", i))?;

            for (i, elem) in self.before_permutation[i].0.iter().enumerate() {
                f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
            }

            for (i, elem) in self.before_permutation[i].1.iter().enumerate() {
                f.write_fmt(format_args!("\r \r y[{}] = {:?}\n", i, elem))?;
            }

            for r in 0..NUM_ROUNDS {
                f.write_fmt(format_args!("round {}: intermediate permutation\n", r))?;

                for (i, elem) in self.intermediate_values_before_constant_additions[i].0[r]
                    .iter()
                    .enumerate()
                {
                    f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
                }

                for (i, elem) in self.intermediate_values_before_constant_additions[i].1[r]
                    .iter()
                    .enumerate()
                {
                    f.write_fmt(format_args!("\r\r y[{}] = {:?}\n", i, elem))?;
                }
            }

            f.write_fmt(format_args!("after permutation: {}\n", i))?;

            for (i, elem) in self.after_permutation[i].0.iter().enumerate() {
                f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
            }

            for (i, elem) in self.after_permutation[i].1.iter().enumerate() {
                f.write_fmt(format_args!("\r \r y[{}] = {:?}\n", i, elem))?;
            }
        }

        f.write_fmt(format_args!("output = {:?}\n", self.output))
    }
}

/// The structure for the trace of the Anemoi-Jive stream cipher.
#[derive(Clone)]
pub struct AnemoiStreamCipherTrace<F: PrimeField, const N: usize, const NUM_ROUNDS: usize> {
    /// The input sequence.
    pub input: Vec<F>,
    /// The state before each permutation.
    pub before_permutation: Vec<([F; N], [F; N])>,
    /// The intermediate values for each permutation.
    pub intermediate_values_before_constant_additions:
        Vec<([[F; N]; NUM_ROUNDS], [[F; N]; NUM_ROUNDS])>,
    /// The state after each permutation.
    pub after_permutation: Vec<([F; N], [F; N])>,
    /// The output.
    pub output: Vec<F>,
}

impl<F: PrimeField, const N: usize, const NUM_ROUNDS: usize> Default
    for AnemoiStreamCipherTrace<F, N, NUM_ROUNDS>
{
    fn default() -> Self {
        Self {
            input: vec![],
            before_permutation: vec![],
            intermediate_values_before_constant_additions: vec![],
            after_permutation: vec![],
            output: vec![],
        }
    }
}

impl<F: PrimeField, const N: usize, const NUM_ROUNDS: usize> ark_std::fmt::Debug
    for AnemoiStreamCipherTrace<F, N, NUM_ROUNDS>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        f.write_str("input:\n")?;
        for (i, elem) in self.input.iter().enumerate() {
            f.write_fmt(format_args!("\r x[{}] = {:?}\n", i, elem))?;
        }
        let chunk_len = if self.input.len() % (2 * N - 1) == 0 {
            self.input.len() / (2 * N - 1)
        } else {
            self.input.len() / (2 * N - 1) + 1
        };

        for i in 0..chunk_len {
            f.write_fmt(format_args!("before permutation: {}\n", i))?;

            for (i, elem) in self.before_permutation[i].0.iter().enumerate() {
                f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
            }

            for (i, elem) in self.before_permutation[i].1.iter().enumerate() {
                f.write_fmt(format_args!("\r \r y[{}] = {:?}\n", i, elem))?;
            }

            for r in 0..NUM_ROUNDS {
                f.write_fmt(format_args!("round {}: intermediate permutation\n", r))?;

                for (i, elem) in self.intermediate_values_before_constant_additions[i].0[r]
                    .iter()
                    .enumerate()
                {
                    f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
                }

                for (i, elem) in self.intermediate_values_before_constant_additions[i].1[r]
                    .iter()
                    .enumerate()
                {
                    f.write_fmt(format_args!("\r\r y[{}] = {:?}\n", i, elem))?;
                }
            }

            f.write_fmt(format_args!("after permutation: {}\n", i))?;

            for (i, elem) in self.after_permutation[i].0.iter().enumerate() {
                f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
            }

            for (i, elem) in self.after_permutation[i].1.iter().enumerate() {
                f.write_fmt(format_args!("\r \r y[{}] = {:?}\n", i, elem))?;
            }
        }

        f.write_str("output:\n")?;
        for (i, elem) in self.output.iter().enumerate() {
            f.write_fmt(format_args!("\r x[{}] = {:?}\n", i, elem))?;
        }

        Ok(())
    }
}
