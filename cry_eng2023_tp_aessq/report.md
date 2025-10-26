Q1 - The `xtime` function is a multiplication of a polynomial `p`by `x` reduced by modulo an irreducible polynomial of deg 8, such as X^8 + X^4 + X^3 + X + 1 (0x11B = 283). It is written as a left shift and a conditional XOR with 0x1b.

Example 1

X^6+X^4+X^2+X+1

m = 01010111 >> 7 => 00000000 
m xor 1 = 00000001
m -= 1 => 00000000
m & 0x1B = 00000000
(p << 1)^m  = p << 1 = 10101110 = 0xAE
X^8
Example 2, iterative application of xtime() to multily (X^6+X^4+X^2+X+1) * (X^4 + X + 1)
57 * 13 = 57 * (0x01 xor 0x02 xor 0x10) = (0x57 * 0x01) xor (0x57 * 0x02) xor (0x57 * 0x10)  
                                        = 0x57 xor 0xAE xor 0x07 = 0xFE

0x13 = 00010011 => 1 xor 2 xor 16 = 0x01 xor 0x02 xor 0x10
0x13 = 00010011 = X^4 + X + 1

0x57 xor 0xAE xor 0x07 = 01010111
                    xor  10101110
                    xor  00000111
                    -------------
                         11111110



Proof of correctness: Regardless of the input polynomial p (conditioned that p fits in 1 byte, that is, having deg < 8) the result of the multiplication by the polynomial X mod m equals a polynomial with degree less than 8, i.e, p * x  = k mod m, where m is an irreducible polynomial and deg k < 8.

p is of the form aX^8 + bX^7+ cX^6 + dX^5 + eX^4 + fX^3 + gX^2 + hX + i, where {a,b,c,d,e,f,g,h,i} \in {0,1}

We have two possibility for the most valuable bit of p: it is either 0 or 1. If 0, we know for a fact that the result is already reduced to a degree < 8 as we only increase the degree of p by one. Thus as 


To implement the function modulo X^8 + X^6 + X^5 + X^4 + X^3 + X + 1 (0x17B = 379)






