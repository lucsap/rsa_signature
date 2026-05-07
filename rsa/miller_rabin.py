import random

def miller_rabin(n, k=40):
    if n < 2:
        return False

    # Casos simples
    for p in [2, 3, 5, 7, 11]:
        if n % p == 0:
            return n == p

    # Escreve n-1 = d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True