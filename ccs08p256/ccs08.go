/*
 * Copyright (C) 2019 ING BANK N.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
This file contains the implementation of the ZKRP scheme proposed in the paper:
Efficient Protocols for Set Membership and Range Proofs
Jan Camenisch, Rafik Chaabouni, abhi shelat
Asiacrypt 2008
*/

package ccs08

import (
    "bytes"
    "crypto/rand"
    "errors"
    "math"
    "math/big"
    "strconv"

    "github.com/aungmawjj/zkrp/crypto/bbsignatures"
    "github.com/aungmawjj/zkrp/crypto/p256"
    . "github.com/aungmawjj/zkrp/util"
    "github.com/aungmawjj/zkrp/util/bn"
    "github.com/aungmawjj/zkrp/util/intconversion"
)

/*
ParamsUL contains elements generated by the verifier, which are necessary for the prover.
This must be computed in a trusted setup.
*/
type ParamsUL struct {
    signatures map[string]*p256.P256
    H          *p256.P256
    kp         bbsignatures.Keypair
    // u determines the amount of signatures we need in the public params.
    // Each signature can be compressed to just 1 field element of 256 bits.
    // Then the parameters have minimum size equal to 256*u bits.
    // l determines how many pairings we need to compute, then in order to improve
    // verifier`s performance we want to minize it.
    // Namely, we have 2*l pairings for the prover and 3*l for the verifier.
    u, l int64
}

/*
ProofUL contains the necessary elements for the ZK proof.
*/
type ProofUL struct {
    V              []*p256.P256
    D, C           *p256.P256
    a              []*p256.P256
    s, t, zsig, zv []*big.Int
    c, m, zr       *big.Int
}

/*
SetupUL generates the signature for the interval [0,u^l).
The value of u should be roughly b/log(b), but we can choose smaller values in
order to get smaller parameters, at the cost of having worse performance.
*/
func SetupUL(u, l int64) (ParamsUL, error) {
    var (
        i int64
        p ParamsUL
    )
    p.kp, _ = bbsignatures.Keygen()

    p.signatures = make(map[string]*p256.P256)
    for i = 0; i < u; i++ {
        sig_i, _ := bbsignatures.Sign(new(big.Int).SetInt64(i), p.kp.Privk)
        p.signatures[strconv.FormatInt(i, 10)] = sig_i
    }
    // Issue #12: p.H must be computed using MapToPoint method.
    h := intconversion.BigFromBase10("18560948149108576432482904553159745978835170526553990798435819795989606410925")
    p.H = new(p256.P256).ScalarBaseMult(h)
    p.u = u
    p.l = l
    return p, nil
}

/*
ProveUL method is used to produce the ZKRP proof that secret x belongs to the interval [0,U^L].
*/
func ProveUL(x, r *big.Int, p ParamsUL) (ProofUL, error) {
    var (
        i         int64
        v         []*big.Int
        proof_out ProofUL
    )
    decx, _ := Decompose(x, p.u, p.l)

    // Initialize variables
    v = make([]*big.Int, p.l)
    proof_out.V = make([]*p256.P256, p.l)
    proof_out.a = make([]*p256.P256, p.l)
    proof_out.s = make([]*big.Int, p.l)
    proof_out.t = make([]*big.Int, p.l)
    proof_out.zsig = make([]*big.Int, p.l)
    proof_out.zv = make([]*big.Int, p.l)
    proof_out.D = new(p256.P256)
    proof_out.D.SetInfinity()
    proof_out.m, _ = rand.Int(rand.Reader, p256.CURVE)

    // D = H^m
    D := new(p256.P256).ScalarMult(p.H, proof_out.m)
    for i = 0; i < p.l; i++ {
        v[i], _ = rand.Int(rand.Reader, p256.CURVE)
        A, ok := p.signatures[strconv.FormatInt(decx[i], 10)]
        if ok {
            proof_out.V[i] = new(p256.P256).ScalarMult(A, v[i])
            proof_out.s[i], _ = rand.Int(rand.Reader, p256.CURVE)
            proof_out.t[i], _ = rand.Int(rand.Reader, p256.CURVE)
            proof_out.a[i] = bn256.Pair(G1, proof_out.V[i])
            proof_out.a[i].ScalarMult(proof_out.a[i], proof_out.s[i])
            proof_out.a[i].Invert(proof_out.a[i])
            proof_out.a[i].Add(proof_out.a[i], new(p256.P256).ScalarMult(E, proof_out.t[i]))

            ui := new(big.Int).Exp(new(big.Int).SetInt64(p.u), new(big.Int).SetInt64(i), nil)
            muisi := new(big.Int).Mul(proof_out.s[i], ui)
            muisi = bn.Mod(muisi, p256.CURVE)
            aux := new(p256.P256).ScalarBaseMult(muisi)
            D.Add(D, aux)
        } else {
            return proof_out, errors.New("Could not generate proof. Element does not belong to the interval.")
        }
    }
    proof_out.D.Add(proof_out.D, D)

    // Consider passing C as input,
    // so that it is possible to delegate the commitment computation to an external party.
    proof_out.C, _ = Commit(x, r, p.H)
    // Fiat-Shamir heuristic
    proof_out.c, _ = Hash(proof_out.a, proof_out.D)
    proof_out.c = bn.Mod(proof_out.c, p256.CURVE)

    proof_out.zr = bn.Sub(proof_out.m, bn.Multiply(r, proof_out.c))
    proof_out.zr = bn.Mod(proof_out.zr, p256.CURVE)
    for i = 0; i < p.l; i++ {
        proof_out.zsig[i] = bn.Sub(proof_out.s[i], bn.Multiply(new(big.Int).SetInt64(decx[i]), proof_out.c))
        proof_out.zsig[i] = bn.Mod(proof_out.zsig[i], p256.CURVE)
        proof_out.zv[i] = bn.Sub(proof_out.t[i], bn.Multiply(v[i], proof_out.c))
        proof_out.zv[i] = bn.Mod(proof_out.zv[i], p256.CURVE)
    }
    return proof_out, nil
}

/*
VerifyUL is used to validate the ZKRP proof. It returns true iff the proof is valid.
*/
func VerifyUL(proof_out *ProofUL, p *ParamsUL) (bool, error) {
    var (
        i      int64
        D      *p256.P256
        r1, r2 bool
        p1, p2 *p256.P256
    )
    // D == C^c.h^ zr.g^zsig ?
    D = new(p256.P256).ScalarMult(proof_out.C, proof_out.c)
    D.Add(D, new(p256.P256).ScalarMult(p.H, proof_out.zr))
    for i = 0; i < p.l; i++ {
        ui := new(big.Int).Exp(new(big.Int).SetInt64(p.u), new(big.Int).SetInt64(i), nil)
        muizsigi := new(big.Int).Mul(proof_out.zsig[i], ui)
        muizsigi = bn.Mod(muizsigi, p256.CURVE)
        aux := new(p256.P256).ScalarBaseMult(muizsigi)
        D.Add(D, aux)
    }

    DBytes := D.Marshal()
    pDBytes := proof_out.D.Marshal()
    r1 = bytes.Equal(DBytes, pDBytes)

    r2 = true
    for i = 0; i < p.l; i++ {
        // a == [e(V,y)^c].[e(V,g)^-zsig].[e(g,g)^zv]
        p1 = bn256.Pair(p.kp.Pubk, proof_out.V[i])
        p1.ScalarMult(p1, proof_out.c)
        p2 = bn256.Pair(G1, proof_out.V[i])
        p2.ScalarMult(p2, proof_out.zsig[i])
        p2.Invert(p2)
        p1.Add(p1, p2)
        p1.Add(p1, new(p256.P256).ScalarMult(E, proof_out.zv[i]))

        pBytes := p1.Marshal()
        aBytes := proof_out.a[i].Marshal()
        r2 = r2 && bytes.Equal(pBytes, aBytes)
    }
    return r1 && r2, nil
}