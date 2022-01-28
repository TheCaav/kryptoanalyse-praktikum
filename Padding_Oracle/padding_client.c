#include <praktikum.h>
#include <network.h>

#include <protocol.h>
#include <my_funcs.h>

Connection con;

// returns 1 if the padding is valid and 0 otherwise
int padding_oracle(unsigned char *buf, char blocks)
{
    if (blocks > 2 || blocks < 1)
    {
        printf("Invalid block count: %d\n", blocks);
        exit(1);
    }
    message req;
    memset(&req, 0, sizeof(req));
    req.type = ORACLE_REQ;
    req.oracle_req.blocks = blocks;
    memcpy(req.oracle_req.ch, buf, sizeof(req.oracle_req.ch));
    Transmit(con, &req, sizeof(req));
    message m;
    ReceiveAll(con, &m, sizeof(m));
    if (m.type != ORACLE_REP)
    {
        printf("Invalid message type from daemon\n");
        exit(1);
    }
    return m.oracle_rep.rep;
}

int sendToOracle(unsigned char *chall, int blocks)
{
    printf("Challenge to Oracle:\n");
    for (int i = 0; i < blocks * BLOCK_LENGTH; i++)
        printf("%d,", chall[i]);
    int rep = padding_oracle(chall, blocks);
    printf("Oracle Reply: %d\n", rep);
    return rep;
}

void sendSolution(unsigned char *buf)
{
    message req;
    memset(&req, 0, sizeof(req));
    req.type = SOLUTION;
    memcpy(req.solution.ch, buf, sizeof(req.solution.ch));
    Transmit(con, &req, sizeof(req));
    message m;
    ReceiveAll(con, &m, sizeof(m));
    if (m.type != SOLUTION_REP)
    {
        printf("Invalid message type from daemon\n");
        exit(1);
    }
    if (m.solution_rep.state == 1)
    {
        printf("AES decryption in daemon failed.\n");
        return;
    }
    if (m.solution_rep.state == 0)
    {
        printf("Solution submitted at %s is correct.\n", Now());
        return;
    }

    printf("Daemon reports decrypted string: ");
    printstring_escaped_unsigned(stdout, m.solution_rep.ch, 2 * BLOCK_LENGTH);
    printf("\n");
    if (m.solution_rep.state == 2)
    {
        printf("Padding is invalid.\n");
    }
    if (m.solution_rep.state == 3)
    {
        printf("String has invalid contents.\n");
    }
}

unsigned char getPaddingLength(unsigned char *chall)
{
    unsigned char tmp[3 * BLOCK_LENGTH];
    unsigned char mask[3 * BLOCK_LENGTH];
    int ind = (2 * BLOCK_LENGTH) - 1;
    unsigned char counter = 0;
    do
    {
        memset(mask, 0, 3 * BLOCK_LENGTH);
        mask[ind] = 255;
        xor_block(chall, mask, tmp, 3 * BLOCK_LENGTH);
        ind--;
        counter++;
    } while (padding_oracle(tmp, 2) == 0);
    printf("Padding length is: %d\n", counter - 1);
    return counter - 1;
}

unsigned char getByteOfCipherByXORing(unsigned char *chall, unsigned char currPadding, unsigned char block)
{
    unsigned char mask[3 * BLOCK_LENGTH];
    unsigned char tmp[3 * BLOCK_LENGTH];
    memset(mask, 0, 3 * BLOCK_LENGTH);
    unsigned char startInd = BLOCK_LENGTH * block - 1;
    for (unsigned char i = 0; i < currPadding; i++)
    {
        mask[startInd - i] = xorIncr(currPadding);
    }
    for (unsigned char i = 0; i < 255; i++)
    {
        mask[startInd - currPadding] = i;
        xor_block(chall, mask, tmp, 3 * BLOCK_LENGTH);
        if (padding_oracle(tmp, block))
        {
            memcpy(chall, tmp, 3 * BLOCK_LENGTH);
            return ((currPadding + 1) ^ i);
        }
    }
    printf("Error!: Couldnt find a working Byte of a Block");
    return 0;
}

unsigned char firstByteOfBlock(unsigned char *chall, unsigned char *to, unsigned char currBlock)
{
    unsigned char tmp[3 * BLOCK_LENGTH];
    memcpy(tmp, chall, 3 * BLOCK_LENGTH);
    for (int i = 0; i < 255; i++)
    {
        tmp[currBlock * BLOCK_LENGTH - 1] = chall[ currBlock * BLOCK_LENGTH - 1] ^ i;
        if (padding_oracle(tmp, currBlock))
        {
            memcpy(to, tmp, 3 * BLOCK_LENGTH);
            return 1 ^ i;
        }
    }
    printf("Error!: Couldnt find a working first Byte of a Block");
    return 0;
}

void decryptCipher(unsigned char *challenge, unsigned char startBlock, unsigned char *solution, unsigned char startPadding)
{
    unsigned char chall[3*BLOCK_LENGTH];
    memcpy(chall, challenge, 3*BLOCK_LENGTH);
    unsigned char currBlock = startBlock;
    unsigned char currPadding = startPadding;
    for (int i = 0; i < BLOCK_LENGTH * startBlock; i++)
    {
        solution[i] = 0;
    }
    for (; currBlock > 0; currBlock--)
    {
        if (currPadding == 0)
        {
            solution[currBlock * BLOCK_LENGTH - 1] = firstByteOfBlock(challenge, chall, currBlock);
            currPadding++;
        }
        for (; currPadding < BLOCK_LENGTH; currPadding++)
        {
            unsigned char decChar = getByteOfCipherByXORing(chall, currPadding, currBlock);
            solution[(currBlock * BLOCK_LENGTH) - currPadding - 1] = decChar;
            //printf("CurrPadding: %u, got ByteVal: %c", currPadding, decChar);
        }
        currPadding = 0;
    }
}

int main(int argc, char *argv[])
{
    con = ConnectTo(MakeNetName(NULL), "Padding_Daemon");
    message m;
    ReceiveAll(con, &m, sizeof(m));
    if (m.type != CHALLENGE)
    {
        printf("Invalid message type from daemon");
        exit(1);
    }
    unsigned char *challenge = m.challenge.ch;
    // Task 1: Obtain the plaintext of challenge
    // Use padding_oracle(data, i);
    //   to send the first BLOCK_LENGTH * i bytes of data to the padding oracle

    unsigned char solution[2 * BLOCK_LENGTH];

    decryptCipher(challenge, 2, solution, getPaddingLength(challenge));
    printf("Lösung für A1 ist: %s\n", solution);
    //for (int i = 0; i < (2*BLOCK_LENGTH) && solution[i] != 0; i++) printf("%c", solution[i]);
    //printf("\n");

    // Task 2: Create a valid ciphertext for the string sol_str.
    // Use  solution(ciphertext); to send the ciphertext for checking.

    unsigned char paddedString[32];
    for (int i = 0; i < 27; i++) {
        paddedString[i] = sol_str[i];
    }
    for (int i = 27; i < 32; i++) {
        paddedString[i] = (unsigned char) 5;
    }

    unsigned char chall[3*BLOCK_LENGTH];
    memcpy(chall, challenge, 3*BLOCK_LENGTH);
    unsigned char C1[BLOCK_LENGTH];
    for (int i = 0; i < BLOCK_LENGTH; i++) {
        C1[i] = chall[BLOCK_LENGTH + i];
    }
    unsigned char M1[BLOCK_LENGTH];
    decryptCipher(chall, 1, M1, 0);
    unsigned char IV1[BLOCK_LENGTH];
    for (int i = 0; i < BLOCK_LENGTH; i++)
    {
        IV1[i] = 0;
    }
    xor_block(chall, M1, IV1, BLOCK_LENGTH);
    xor_block(IV1, paddedString + (sizeof(char) * BLOCK_LENGTH), IV1, BLOCK_LENGTH); //IV1 = IV ^ M1 ^ SOL2

    for (int i = 0; i < BLOCK_LENGTH; i++)
    {
        chall[BLOCK_LENGTH + i] = IV1[i];
    }
    unsigned char M2[BLOCK_LENGTH];
    decryptCipher(chall, 1, M2, 0);
    unsigned char IV2[BLOCK_LENGTH];
    for (int i = 0; i < BLOCK_LENGTH; i++)
    {
        IV2[i] = 0;
    }
    xor_block(chall, M2, IV2, BLOCK_LENGTH);
    xor_block(IV2, paddedString, IV2, BLOCK_LENGTH); // IV2 = IV ^ M2 ^ SOL1

    unsigned char sol[3*BLOCK_LENGTH];
    for (int i = 0; i < BLOCK_LENGTH; i++) sol[i] = IV2[i];
    for (int i = 0; i < BLOCK_LENGTH; i++) sol[BLOCK_LENGTH + i] = IV1[i];
    for (int i = 0; i < BLOCK_LENGTH; i++) sol[2*BLOCK_LENGTH + i] = C1[i];

    //getPaddingLength(sol);

    sendSolution(sol);

    DisConnect(con);
    exit(0);

    return 0;
}
