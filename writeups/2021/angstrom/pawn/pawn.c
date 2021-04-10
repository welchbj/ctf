#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define tiles 8
#define bc 5

// who needs good code when you have macro spam
// also gotta parenthesize everything just in case
// also I apologize to anyone trying to understand my code
#define PEQ(A, B, C, D) (((A) == (C) && (B) == (D)) || ((A) == (D) && (B) == (C)))
#define PEQS(A, B, C, D) ((A) == (C) && (B) == (D))
#define ABS(A) (((A) < 0) ? -(A) : (A))
#define MIN(A, B) (((A) < (B)) ? (A) : (B))
#define MAX(A, B) (((A) > (B)) ? (A) : (B))
#define ITER(A, B, C) for (int C = MIN(A, B); C < MAX(A, B); C++)
#define RETI(A, B, C) for (int C = MAX(A, B); C > MIN(A, B); C--)
#define ITEREQ(A, B, C) for (int C = MIN(A, B); C <= MAX(A, B); C++)
#define RETIEQ(A, B, C) for (int C = MAX(A, B); C >= MIN(A, B); C--)
#define ITERNEQ(A, B, C) for (int C = MIN(A, B) + 1; C < MAX(A, B); C++)
#define RETINEQ(A, B, C) for (int C = MAX(A, B) - 1; C > MIN(A, B); C--)
#define DIR(A, B) (((A) == (B)) ? 0 : ((A) < (B)) ? 1 : -1)
#define GOTO(A, B, C) for (int C = (A); C != (B); C += DIR(A, B))
#define GOTOEQ(A, B, C) for (int C = (A); C != (B) + DIR(A, B); C += DIR(A, B))
#define GOTONEQ(A, B, C) for (int C = (A) + DIR(A, B); C != (B); C += DIR(A, B))

int t = 0;
char** boards[bc];
char starting[] =
    "RNBKQBNR\x00PPPPPPPP\x00........\x00........\x00........\x00........"
    "\x00pppppppp\x00rnbkqbnr";

// bitwise magic is magical
int is_lower_case(char c) { return c & 0x20; }

int is_upper_case(char c) { return !is_lower_case(c); }

char to_lower_case(char c) { return c | 0x20; }

char to_upper_case(char c) { return c & (~0x20); }

int is_letter(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

char* make_board(char** b) {
    char* bigmem = (char*)malloc(tiles * (tiles + 1) * sizeof(char));
    memcpy(bigmem, starting, sizeof(starting));
    for (int i = 0; i < tiles; i++) {
        b[i] = bigmem + i * 9;
    }
    return bigmem;
}

void print_board(char** b) {
    printf("  ");
    for (int i = 0; i < tiles; i++) {
        printf("%d", i);
    }
    puts("-x");
    for (int i = 0; i < tiles; i++) {
        printf("%d %s\n", i, b[i]);
    }
    puts("|\ny");
}

int move_piece(char** b, int ox, int oy, int nx, int ny) {
    char piece = b[oy][ox];
    if (!is_letter(piece)) {
        return 1;
    }
    char low = to_lower_case(piece);
    // standing still instead of moving
    if (PEQS(ox, oy, nx, ny)) {
        return 1;
    }
    // piece is on the same team
    if (is_letter(b[ny][nx]) &&
        is_lower_case(b[ny][nx]) == is_lower_case(piece)) {
        return 1;
    }
    if (low == 'p') {
        // pawns take forwards and don't have en passant
        // also they can jump over a piece on their starting move
        // deal with it
        if (nx != ox) {
            return 1;
        }
        int offset, dub;
        if (is_lower_case(piece)) {
            offset = oy - ny;
            dub = oy == tiles - 2;
        } else {
            offset = ny - oy;
            dub = oy == 1;
        }
        if (offset != 1 && !(offset == 2 && dub)) {
            return 1;
        }
    } else if (low == 'r') {
        if (ox != nx && oy != ny) {
            return 1;
        }
        if (ox == nx) {
            ITERNEQ(oy, ny, i) {
                if (is_letter(b[i][ox])) {
                    return 1;
                }
            }
        } else {
            ITERNEQ(ox, nx, i) {
                if (is_letter(b[oy][i])) {
                    return 1;
                }
            }
        }
    } else if (low == 'n') {
        if (!PEQ(ABS(nx - ox), ABS(ny - oy), 2, 1)) {
            return 1;
        }
    } else if (low == 'b') {
        int dx = ox - nx;
        int dy = oy - ny;
        if (ABS(dx) != ABS(dy)) {
            return 1;
        }
        GOTONEQ(0, dx, i) {
            if (is_letter(b[oy + i * DIR(oy, ny)][ox + i * DIR(ox, nx)])) {
                return 1;
            }
        }
    } else if (low == 'k') {
        // check detection is nonexistent
        // deal with it
        if (ABS(ox - nx) > 1 || ABS(oy - ny) > 1) {
            return 1;
        }
    } else if (low == 'q') {
        int dx = ox - nx;
        int dy = oy - ny;
        if (!dx || !dy) {
            if (ox == nx) {
                ITERNEQ(oy, ny, i) {
                    if (is_letter(b[i][ox])) {
                        return 1;
                    }
                }
            } else {
                ITERNEQ(ox, nx, i) {
                    if (is_letter(b[oy][i])) {
                        return 1;
                    }
                }
            }
        } else if (ABS(dx) == ABS(dy)) {
            GOTONEQ(0, dx, i) {
                if (is_letter(b[oy + i * DIR(oy, ny)][ox + i * DIR(ox, nx)])) {
                    return 1;
                }
            }
        }
        return 1;
    } else {
        return 1;
    }
    b[ny][nx] = piece;
    b[oy][ox] = '.';
    return 0;
}

int smite_piece(char** b, int x, int y) {
    if (is_letter(b[y][x])) {
        b[y][x] = t;
        return 0;
    }
    return 1;
}

int readint() {
    int ret;
    scanf("%d", &ret);
    return ret;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
    for (int i = 0; i < bc; i++) {
        boards[i] = NULL;
    }
    while (1) {
        puts("What would you like to do?");
        puts("1) New Board");
        puts("2) Print Board");
        puts("3) Move Piece");
        puts("4) Smite Piece");
        puts("5) Delete Board");
        int action = readint();
        if (action == 1) {
            puts("What is the board index?");
            int ind = readint();
            if (ind < 0 || ind > 4) {
                puts("The board index must be from 0-4");
                continue;
            }
            boards[ind] = (char**)malloc(tiles * sizeof(char*));
            make_board(boards[ind]);
        } else if (action == 2) {
            puts("What is the board index?");
            int ind = readint();
            if (ind < 0 || ind > 4) {
                puts("The board index must be from 0-4");
                continue;
            }
            printf("Board %d:\n", ind);
            print_board(boards[ind]);
        } else if (action == 3) {
            puts("What is the board index?");
            int ind = readint();
            if (ind < 0 || ind > 4) {
                puts("The board index must be from 0-4");
                continue;
            }
            int ox, oy, nx, ny;
            puts(
                "Please provide the x and y values of the piece, separated by "
                "spaces.");
            scanf("%d %d", &ox, &oy);
            puts(
                "Please provide the x and y values of the position to move to, "
                "separated by spaces.");
            scanf("%d %d", &nx, &ny);
            if (move_piece(boards[ind], ox, oy, nx, ny)) {
                puts("Invalid move.");
            } else {
                puts("Move made.");
                t ++;
            }
        } else if (action == 4) {
            puts("What is the board index?");
            int ind = readint();
            if (ind < 0 || ind > 4) {
                puts("The board index must be from 0-4");
                continue;
            }
            int ox, oy;
            puts(
                "Please provide the x and y values of the piece, separated by "
                "spaces.");
            scanf("%d %d", &ox, &oy);
            if (smite_piece(boards[ind], ox, oy)) {
                puts("Smite failed.");
            } else {
                puts("Piece smotenified.");
            }
        } else if (action == 5) {
            puts("What is the board index?");
            int ind = readint();
            if (ind < 0 || ind > 4) {
                puts("The board index must be from 0-4");
                continue;
            }
            free(boards[ind][0]);
            free(boards[ind]);
        } else {
            puts("I don't know what that is.");
        }
    }
}
