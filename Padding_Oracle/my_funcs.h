/**
 * Find x such that n xor x = n + 1
 * return x
 */
static unsigned char xorIncr(unsigned char n) {
    unsigned char x = 0;
    for (unsigned char e = 0; e < 8; e++) {
        unsigned char mask = 1 << e;
        x |= mask;
        //printf("n and mask: %u, ", x);
        if ((n & mask) == 0) {
            break;
        }
    }
    return x;
}