def d_term(x, s):
    numer = (2 ** 225)
    denom = 1
    result = numer // denom
    pi20 = 314159265358979323846#26433832795028841971693993751058209749445923078164
    for i in range(300):
        numer = numer * pi20
        numer = numer * (x * x)

        denom = denom * (i + 1)
        denom = denom * (s * s)
        denom = denom * (10 ** 20)
        taylor = numer // denom

        if i % 2 == 0:
            taylor = -taylor
        result = result + taylor
    return result // s


if __name__ == "__main__":
    f = open('tmp.txt', 'w')

    s = 2366500
    iteration = 100

    table = []
    for i in range(iteration):
        if i == 0:
            table.append(0)
        else:
            table.append(table[-1] + d_term(i, s))
        print("present compute : " + str(i))
    for i in range(iteration):
        table[i] = table[i] + ((2 ** 224) // s)

    for value in table:
        f.write(hex(value >> (32 + 128)))
        f.write('\n')
