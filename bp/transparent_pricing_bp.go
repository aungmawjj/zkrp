package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ing-bank/zkrp/bulletproofs"
	"github.com/ing-bank/zkrp/crypto/p256"
	"github.com/ing-bank/zkrp/util"
)

type System struct {
	users   map[int]*User
	company Company
}

type User struct {
	gamma    int64
	delta    int64
	nUsers   int
	idx      int
	reading  int
	r        *big.Int
	commits1 map[int][]byte
	commits2 map[int][]byte
	proofs   map[int][]byte
	sumProof []byte
}

type UserJSON struct {
	Gamma    int64
	Delta    int64
	NUsers   int
	Idx      int
	Reading  int
	R        *big.Int
	Commits1 map[int][]byte
	Commits2 map[int][]byte
	Proofs   map[int][]byte
	SumProof []byte
}

type Company struct {
	gamma    int64
	delta    int64
	nUsers   int
	readings map[int]int
	sum      int
	rs       map[int]*big.Int
	commits1 map[int][]byte
	commits2 map[int][]byte
	proofs   map[int][]byte
	sumProof []byte
}

func (s *System) drawReadings(maxN int) {
	for i := 0; i < s.company.nUsers; i++ {
		s.users[i].reading = rand.Intn(maxN)
		fmt.Println(s.users[i].reading)
	}
}

func (s *System) shareReadings() {
	s.company.readings = make(map[int]int)
	for i := 0; i < s.company.nUsers; i++ {
		s.users[i].shareReading(&s.company)
	}
}

func (u *User) shareReading(c *Company) {
	c.readings[u.idx] = u.reading
}

func (c *Company) processReadings() {
	c.sum = 0
	c.proofs = make(map[int][]byte)
	c.commits1 = make(map[int][]byte)
	c.commits2 = make(map[int][]byte)
	sumR := big.NewInt(int64(0))
	for i := 0; i < c.nUsers; i++ {
		c.sum = c.sum + c.readings[i]
		sumR = new(big.Int).Add(sumR, c.rs[i])
	}
	fmt.Println("sum:", c.sum)
	wg := new(sync.WaitGroup)
	for i := 0; i < c.nUsers; i++ {
		wg.Add(1)
		go c.generateProof(i, wg)
	}

	psum, _ := bulletproofs.SetupGeneric(c.gamma, c.delta*int64(c.nUsers))
	sumProof, _ := bulletproofs.ProveGeneric(big.NewInt(int64(c.sum)), psum, sumR)
	c.sumProof, _ = json.Marshal(sumProof)

	wg.Wait()

	// // sanity check

	// p, _ := bulletproofs.SetupGeneric(0, c.delta)
	// eta, _ := util.CommitG1(big.NewInt(int64(10)), big.NewInt(int64(10)), p.BP2.H)
	// zeta, _ := util.CommitG1(big.NewInt(int64(10-c.gamma)), big.NewInt(int64(10)), p.BP2.H)
	// sumV2 := new(p256.P256).Add(sumProof.P2.V, eta)
	// var (
	// 	cm    *p256.P256
	// 	cStar *p256.P256
	// )
	// _ = json.Unmarshal(c.commits2[0], &cStar)
	// for i := 1; i < c.nUsers; i++ {
	// 	_ = json.Unmarshal(c.commits2[i], &cm)
	// 	cStar = new(p256.P256).Add(cStar, cm)
	// }
	// //    _ = json.Unmarshal(c.commits2[0], &cStar)
	// //    _ = json.Unmarshal(c.commits2[1], &cm)
	// //    cStar = new(p256.P256).Add(cStar, cm)
	// cStar = new(p256.P256).Add(cStar, zeta)

	// fmt.Println(sumV2.Equals(cStar))
}

var proofMtx sync.Mutex

func (c *Company) generateProof(idx int, wg *sync.WaitGroup) {
	defer wg.Done()
	p, _ := bulletproofs.SetupGeneric(0, c.delta)
	proof, _ := bulletproofs.ProveGeneric(big.NewInt(int64(c.readings[idx])), p, c.rs[idx])

	proofMtx.Lock()
	defer proofMtx.Unlock()
	c.proofs[idx], _ = json.Marshal(proof)
	c.commits1[idx], _ = json.Marshal(proof.P1.V)
	c.commits2[idx], _ = json.Marshal(proof.P2.V)
}

//func (c *Company) processReadingsMaliciously() {
//    c.sum = 0
//    c.proofs = make(map[int][]byte)
//    c.commits1 = make(map[int][]byte)
//    c.commits2 = make(map[int][]byte)
//    c.sumR = big.NewInt(int64(0))
//    p, _ := bulletproofs.SetupGeneric(0, c.d)
//    for i:=0;i<c.nUsers;i++ {
//        c.sum = c.sum + c.readings[i]
//        proof1, _ := bulletproofs.ProveGeneric(big.NewInt(int64(c.readings[i])), p, c.rs[i])
//        proof2, _ := bulletproofs.ProveGeneric(big.NewInt(int64(c.d-1)), p, c.rs[i])
//        proof2.P1.V = proof1.P1.V
//        proof2.P2.V = proof1.P2.V
//        c.proofs[i], _ = json.Marshal(proof2)
//        c.commits1[i], _ = json.Marshal(proof2.P1.V)
//        c.commits2[i], _ = json.Marshal(proof2.P2.V)
//        rand.Seed(c.rs[i])
//        c.sumR.Add(c.sumR, big.NewInt(int64(rand.Int())))
//    }
//}

func (s *System) shareProofData() {
	for i := 0; i < s.company.nUsers; i++ {
		s.company.shareProofData(s.users[i])
	}
}

func (c *Company) shareProofData(u *User) {
	u.proofs = make(map[int][]byte)
	u.commits1 = make(map[int][]byte)
	u.commits2 = make(map[int][]byte)
	for key, value := range c.proofs {
		u.proofs[key] = value
	}
	for key, value := range c.commits1 {
		u.commits1[key] = value
	}
	for key, value := range c.commits2 {
		u.commits2[key] = value
	}
	u.sumProof = c.sumProof
}

func (u *User) checkCommitment() {
	var (
		commit1 *p256.P256
		commit2 *p256.P256
	)
	params, _ := bulletproofs.SetupGeneric(0, u.delta)
	V1, _ := util.CommitG1(big.NewInt(int64(u.reading)-u.delta+bulletproofs.MAX_RANGE_END), u.r, params.BP1.H) // note: params.BP1.H = params.BP2.H
	V2, _ := util.CommitG1(big.NewInt(int64(u.reading)), u.r, params.BP2.H)
	_ = json.Unmarshal(u.commits1[u.idx], &commit1)
	_ = json.Unmarshal(u.commits2[u.idx], &commit2)

	check := V1.Equals(commit1) && V2.Equals(commit2)
	if check {
		fmt.Println("check 1 for user", u.idx, "succeeded")
	} else {
		fmt.Println("check 1 for user", u.idx, "FAILED")
	}
}

func (u *User) checkSumProof() {
	var (
		sumProof bulletproofs.ProofBPRP
		commit1  *p256.P256
		commit2  *p256.P256
		Cstar1   *p256.P256
		Cstar2   *p256.P256
	)
	p, _ := bulletproofs.SetupGeneric(u.gamma, u.delta*int64(u.nUsers))
	_ = json.Unmarshal(u.sumProof, &sumProof)
	_ = json.Unmarshal(u.commits1[0], &Cstar1)
	_ = json.Unmarshal(u.commits2[0], &Cstar2)

	// it's impossible (due to nature of elliptic curves or bug in zkrp code?) to commit(x,r,p) using x = 0 or r = 0, or to compute c(x,r,p) + c(x,r,p)
	// to get around this, we need to add a non-zero dummy to both commitments
	dummy := int64(10)

	eta1, _ := util.CommitG1(big.NewInt(int64(dummy-u.delta*int64(u.nUsers)+bulletproofs.MAX_RANGE_END*int64(u.nUsers))), big.NewInt(int64(dummy)), p.BP2.H)
	zeta1, _ := util.CommitG1(big.NewInt(int64(dummy-u.delta*int64(u.nUsers)+bulletproofs.MAX_RANGE_END)), big.NewInt(int64(dummy)), p.BP2.H)
	eta2, _ := util.CommitG1(big.NewInt(int64(dummy)), big.NewInt(int64(dummy)), p.BP2.H)
	zeta2, _ := util.CommitG1(big.NewInt(int64(dummy-u.gamma)), big.NewInt(int64(dummy)), p.BP2.H)

	for i := 1; i < len(u.commits2); i++ {
		_ = json.Unmarshal(u.commits1[i], &commit1)
		_ = json.Unmarshal(u.commits2[i], &commit2)
		Cstar1 = new(p256.P256).Add(Cstar1, commit1)
		Cstar2 = new(p256.P256).Add(Cstar2, commit2)
	}

	sumV1 := new(p256.P256).Add(sumProof.P1.V, eta1)
	Cstar1 = new(p256.P256).Add(Cstar1, zeta1)
	sumV2 := new(p256.P256).Add(sumProof.P2.V, eta2)
	Cstar2 = new(p256.P256).Add(Cstar2, zeta2)

	ok1 := sumV1.Equals(Cstar1)
	if !ok1 {
		fmt.Println("failure in check 2 for user", u.idx, ": commitment 1 did not match sum")
	}

	ok2 := sumV2.Equals(Cstar2)
	if !ok2 {
		fmt.Println("failure in check 2 for user", u.idx, ": commitment 2 did not match sum")
	}

	ok3, _ := sumProof.Verify()
	if !ok3 {
		fmt.Println("range proof failed in check 2 for user", u.idx)
	}

	if ok1 && ok2 && ok3 {
		fmt.Println("check 2 for user", u.idx, "succeeded, can charge peak rate")
	} else {
		if ok1 && ok2 {
			fmt.Println("check 2 for user", u.idx, "succeeded, but CANNOT charge peak rate")
		} else {
			fmt.Println("check 2 for user", u.idx, "FAILED")
		}
	}
}

func (u *User) checkRangeProofs() {
	var mtx sync.Mutex
	var wg sync.WaitGroup
	noFailures := true
	for i := 0; i < len(u.proofs); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var (
				proof   bulletproofs.ProofBPRP
				commit1 *p256.P256
				commit2 *p256.P256
			)
			_ = json.Unmarshal(u.proofs[i], &proof)
			_ = json.Unmarshal(u.commits1[i], &commit1)
			_ = json.Unmarshal(u.commits2[i], &commit2)

			ok1 := proof.P1.V.Equals(commit1)
			if !ok1 {
				fmt.Println("failure in check 3 for user", u.idx, ": commitment 1 did not match")
			}
			ok2 := proof.P2.V.Equals(commit2)
			if !ok2 {
				fmt.Println("failure in check 3 for user", u.idx, ": commitment 2 did not match")
			}
			ok3, _ := proof.Verify()
			if !ok3 {
				fmt.Println("failure in check 3 for user", u.idx, ": invalid proof")
			}
			mtx.Lock()
			defer mtx.Unlock()
			if noFailures {
				noFailures = noFailures && ok1 && ok2 && ok3
			}
		}(i)
	}
	wg.Wait()

	if noFailures {
		fmt.Println("check 3 for user", u.idx, "succeeded")
	} else {
		fmt.Println("check 3 for user", u.idx, "FAILED")
	}
}

func (s *System) checkProofsSingleUser() {
	s.users[0].checkProofs()
}

func (s *System) checkProofsAllUsers() {
	for i := 0; i < s.company.nUsers; i++ {
		s.users[i].checkProofs()
	}
}

func (u *User) checkProofs() {
	u.checkCommitment()
	u.checkSumProof()
	u.checkRangeProofs()
}

func initialize(n int, gamma int64, delta int64) System {
	users := make(map[int]*User)
	rs := make(map[int]*big.Int)
	for i := 0; i < n; i++ {
		r := big.NewInt(int64(rand.Int()))
		users[i] = &User{gamma, delta, n, i, 0, r, nil, nil, nil, nil}
		rs[i] = r
	}
	company := Company{gamma, delta, n, nil, 0, rs, nil, nil, nil, nil}
	return System{users, company}
}

//func Sanity() {
//    pa, _ := bulletproofs.SetupGeneric(0, 20)
//    pb, _ := bulletproofs.SetupGeneric(0, 20)
//    pc, _ := bulletproofs.SetupGeneric(10, 20)
//    proofa, _ := bulletproofs.ProveGeneric(big.NewInt(int64(5)),  pa, big.NewInt(int64(1200)))
//    proofb, _ := bulletproofs.ProveGeneric(big.NewInt(int64(10)),  pb, big.NewInt(int64(1200)))
//    proofc, _ := bulletproofs.ProveGeneric(big.NewInt(int64(25)), pc, big.NewInt(int64(2400)))
//
//    commit1a, _ := util.CommitG1(big.NewInt(int64(5) - 20 + bulletproofs.MAX_RANGE_END), big.NewInt(int64(1200)), pa.BP2.H)
//    commit2a, _ := util.CommitG1(big.NewInt(int64(5)), big.NewInt(int64(1200)), pa.BP2.H)
//    commit1b, _ := util.CommitG1(big.NewInt(int64(10) - 20 + bulletproofs.MAX_RANGE_END), big.NewInt(int64(1200)), pb.BP2.H)
//    commit2b, _ := util.CommitG1(big.NewInt(int64(15)), big.NewInt(int64(600)), pb.BP2.H)
//    commit2bsum, _ := util.CommitG1(big.NewInt(-5), big.NewInt(int64(600)), pb.BP2.H)
//    commit2b.Add(commit2b, commit2bsum)
//
//    commitabsum := new(p256.P256).Add(commit2a, commit2b)
//
//    fmt.Println(proofa.P1.V.Equals(commit1a))
//    fmt.Println(proofa.P2.V.Equals(commit2a))
//    fmt.Println(proofb.P1.V.Equals(commit1b))
//    fmt.Println(proofb.P2.V.Equals(commit2b))
//    fmt.Println(proofc.P2.V.Equals(commitabsum))
//}

func main() {
	//    Sanity()
	if len(os.Args) < 2 {
		return
	}
	fmt.Println(os.Args[1])
	if os.Args[1] == "c" {
		nUsers, err := strconv.Atoi(os.Args[2])
		check(err)
		startTime := time.Now().UnixNano()
		system := initialize(nUsers, 500, 120)
		system.drawReadings(100)
		system.shareReadings()
		shareReadingsTime := time.Now().UnixNano()
		system.company.processReadings()
		system.shareProofData()
		processReadingsTime := time.Now().UnixNano()
		fmt.Println("sharing:", float64(shareReadingsTime-startTime)/1000000000, "seconds")
		fmt.Println("processing:", float64(processReadingsTime-shareReadingsTime)/1000000000, "seconds")

		uj := UserJSON{
			Gamma:    system.users[0].gamma,
			Delta:    system.users[0].delta,
			NUsers:   system.users[0].nUsers,
			Idx:      system.users[0].idx,
			Reading:  system.users[0].reading,
			R:        system.users[0].r,
			Commits1: system.users[0].commits1,
			Commits2: system.users[0].commits2,
			Proofs:   system.users[0].proofs,
			SumProof: system.users[0].sumProof,
		}
		f, _ := os.Create("user.json")
		defer f.Close()
		e := json.NewEncoder(f)
		e.Encode(uj)
	} else if os.Args[1] == "u" {
		var uj UserJSON
		f, _ := os.Open("user.json")
		defer f.Close()
		d := json.NewDecoder(f)
		d.Decode(&uj)
		user := User{
			gamma:    uj.Gamma,
			delta:    uj.Delta,
			nUsers:   uj.NUsers,
			idx:      uj.Idx,
			reading:  uj.Reading,
			r:        uj.R,
			commits1: uj.Commits1,
			commits2: uj.Commits2,
			proofs:   uj.Proofs,
			sumProof: uj.SumProof,
		}
		startTime := time.Now().UnixNano()
		user.checkProofs()
		checkReadingsTime := time.Now().UnixNano()
		fmt.Println("check time:", float64(checkReadingsTime-startTime)/1000000000, "seconds")
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
