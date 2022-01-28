#define BLOCK_LENGTH 16

enum message_type {
  CHALLENGE,
  ORACLE_REQ,
  ORACLE_REP,
  SOLUTION,
  SOLUTION_REP};

static const char *sol_str = "Dieser Versuch ist geloest.";

typedef struct message {
  enum message_type type;
  union {
    struct {
      unsigned char ch[3 * BLOCK_LENGTH];
    } challenge;
    struct {
      unsigned char ch[3 * BLOCK_LENGTH];
      char blocks;
    } oracle_req;
    struct {
      char rep;
    } oracle_rep;
    struct {
      unsigned char ch[3 * BLOCK_LENGTH];
    } solution;
    struct {
      unsigned char ch[2 * BLOCK_LENGTH]; // For debugging
      char state; // 1 = AES decryption failed, 2 = Padding is invalid, 3 = String is invalid, 0 = Solution is correct
    } solution_rep;
  };
} message;

static void xor_block(const unsigned char *a, const unsigned char *b, unsigned char *to, int len){
  for(int i = 0; i < len; i++){
    to[i] = a[i] ^ b[i];
  }
}
