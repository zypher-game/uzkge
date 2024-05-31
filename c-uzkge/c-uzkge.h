#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Bytes {
  uint32_t len;
  const uint8_t *data;
} Bytes;

typedef struct CardParam {
  struct Bytes x1;
  struct Bytes y1;
  struct Bytes x2;
  struct Bytes y2;
} CardParam;

int32_t __point_add(const uint8_t *x1,
                    const uint8_t *y1,
                    const uint8_t *x2,
                    const uint8_t *y2,
                    uint8_t *ret_val);

int32_t __scalar_mul(const uint8_t *s, const uint8_t *x, const uint8_t *y, uint8_t *ret_val);

int32_t __anemoi_hash(const struct Bytes *data, uint32_t data_len, uint8_t *ret_val);

int32_t __generate_shuffle_proof(struct Bytes rng_seed,
                                 struct Bytes pk,
                                 const struct CardParam *inputs_param,
                                 uint32_t inputs_len,
                                 uint32_t n_cards,
                                 uint8_t *ret_val,
                                 uint32_t ret_len);

int32_t __verify_shuffle(struct Bytes verifier_params,
                         const struct CardParam *inputs_param,
                         uint32_t inputs_len,
                         const struct CardParam *outputs_param,
                         uint32_t outputs_len,
                         struct Bytes proof);

int32_t __verifier_matchmaking_params(uint8_t *ret_val, uint32_t ret_len);

int32_t __generate_matchmaking_proof(struct Bytes verifier_params,
                                     struct Bytes rng_seed,
                                     const struct Bytes *inputs_param,
                                     uint32_t inputs_len,
                                     struct Bytes committed_seed,
                                     struct Bytes random_number,
                                     uint8_t *ret_val,
                                     uint32_t ret_len);

int32_t __verify_matchmaking(struct Bytes verifier_params,
                             const struct Bytes *inputs_param,
                             uint32_t inputs_len,
                             const struct Bytes *outputs_param,
                             uint32_t outputs_len,
                             struct Bytes commitment,
                             struct Bytes random_number,
                             struct Bytes proof);
